package pet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestDailyRecordAcceptsDateOnlyAndRFC3339Dates(t *testing.T) {
	var dateOnly DailyRecord
	if err := json.Unmarshal([]byte(`{"orderId":7,"recordDate":"2026-08-20","diet":"正常"}`), &dateOnly); err != nil {
		t.Fatalf("date-only record JSON error = %v", err)
	}
	if got := dateOnly.RecordDate.Format("2006-01-02"); got != "2026-08-20" {
		t.Fatalf("date-only record date = %s", got)
	}

	stamp := time.Date(2026, 8, 20, 8, 30, 0, 0, time.UTC)
	input, err := json.Marshal(struct {
		RecordDate time.Time `json:"recordDate"`
	}{RecordDate: stamp})
	if err != nil {
		t.Fatal(err)
	}
	var timestamp DailyRecord
	if err := json.Unmarshal(input, &timestamp); err != nil {
		t.Fatalf("RFC3339 record JSON error = %v", err)
	}
	if !timestamp.RecordDate.Equal(stamp) {
		t.Fatalf("RFC3339 record date = %s", timestamp.RecordDate)
	}
}

func testService(t *testing.T) (*Service, func()) {
	t.Helper()
	store, err := Open(context.Background(), "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(store)
	now := time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)
	service.withNow(func() time.Time { return now })
	return service, func() { _ = store.Close() }
}

func loginAs(t *testing.T, service *Service, username, password string) Principal {
	t.Helper()
	token, _, _, err := service.Login(context.Background(), username, password)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := service.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

func TestSessionLifecycleAndRoleAuthorization(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	admin := loginAs(t, service, "admin", "admin123")
	userToken, _, _, err := service.Login(context.Background(), "testuser", "user123")
	if err != nil {
		t.Fatal(err)
	}
	user, err := service.Authenticate(context.Background(), userToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AddRoom(context.Background(), user, Room{Number: "D101", Type: "STANDARD", Status: "AVAILABLE", PricePerDay: 88, Capacity: 1}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("user add room error = %v", err)
	}
	if _, err := service.AddRoom(context.Background(), admin, Room{Number: "D101", Type: "STANDARD", Status: "AVAILABLE", PricePerDay: 88, Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	if err := service.Logout(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(context.Background(), userToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("authenticate revoked token error = %v", err)
	}
}

func TestDisabledUserAndPasswordChangesRevokeExistingSessions(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")

	userToken, user, _, err := service.Login(ctx, "testuser", "user123")
	if err != nil {
		t.Fatal(err)
	}
	user.Status = 0
	if _, err := service.UpdateUser(ctx, admin, user); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, userToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("disabled account token error = %v", err)
	}

	user.Status = 1
	if _, err := service.UpdateUser(ctx, admin, user); err != nil {
		t.Fatal(err)
	}
	if err := service.ResetPassword(ctx, admin, user.ID, "newpass123"); err != nil {
		t.Fatal(err)
	}
	newToken, _, _, err := service.Login(ctx, "testuser", "newpass123")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := service.Authenticate(ctx, newToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ChangePassword(ctx, principal, "newpass123", "finalpass123"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, newToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("password change token error = %v", err)
	}
}

func TestOrderLifecyclePersistsRelatedEntities(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	petItem, err := service.AddPet(ctx, user, Pet{Name: "豆豆", Type: "DOG", Breed: "柯基", HealthStatus: "健康"})
	if err != nil {
		t.Fatal(err)
	}
	rooms, err := service.AvailableRooms(ctx, user, "STANDARD")
	if err != nil || len(rooms) == 0 {
		t.Fatalf("rooms=%v err=%v", rooms, err)
	}
	services, err := service.AvailableServices(ctx, user)
	if err != nil || len(services) == 0 {
		t.Fatalf("services=%v err=%v", services, err)
	}
	start := time.Date(2026, 8, 21, 2, 0, 0, 0, time.UTC)
	order, err := service.CreateOrder(ctx, user, CreateOrderInput{PetID: petItem.ID, RoomID: rooms[0].ID, StartTime: start, EndTime: start.Add(48 * time.Hour), Services: []OrderService{{ServiceID: services[0].ID, Quantity: 2}}})
	if err != nil {
		t.Fatal(err)
	}
	if order.Status != "PENDING" || order.TotalAmount <= 0 {
		t.Fatalf("order=%+v", order)
	}
	for _, state := range []string{"CONFIRMED", "IN_PROGRESS"} {
		if err := service.UpdateOrderStatus(ctx, admin, order.ID, state); err != nil {
			t.Fatal(err)
		}
	}
	record, err := service.AddRecord(ctx, admin, DailyRecord{OrderID: order.ID, RecordDate: start, Diet: "正常", Activity: "活跃", Spirit: "良好"})
	if err != nil {
		t.Fatal(err)
	}
	if record.ID == 0 {
		t.Fatal("record id missing")
	}
	if err := service.UpdateOrderStatus(ctx, admin, order.ID, "COMPLETED"); err != nil {
		t.Fatal(err)
	}
	reloaded, err := service.GetOrder(ctx, user, order.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Status != "COMPLETED" {
		t.Fatalf("status=%s", reloaded.Status)
	}
}

func TestConcurrentRoomCapacityIsNotOversold(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	user := loginAs(t, service, "testuser", "user123")
	room, err := service.AddRoom(ctx, loginAs(t, service, "admin", "admin123"), Room{Number: "RACE-1", Type: "STANDARD", Status: "AVAILABLE", PricePerDay: 100, Capacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	pets := make([]Pet, 2)
	for i := range pets {
		pets[i], err = service.AddPet(ctx, user, Pet{Name: fmt.Sprintf("并发宠物%d", i), Type: "DOG"})
		if err != nil {
			t.Fatal(err)
		}
	}
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	gate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	results := make(chan error, 2)
	for i := range pets {
		go func(index int) {
			defer wg.Done()
			<-gate
			_, err := service.CreateOrder(ctx, user, CreateOrderInput{PetID: pets[index].ID, RoomID: room.ID, StartTime: start, EndTime: start.Add(24 * time.Hour)})
			results <- err
		}(i)
	}
	close(gate)
	wg.Wait()
	close(results)
	success := 0
	conflict := 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflict++
		} else {
			t.Fatalf("unexpected err=%v", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
}

func TestRestartRestoresPetData(t *testing.T) {
	path := t.TempDir() + "/pet.db"
	ctx := context.Background()
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(store)
	user := loginAs(t, service, "testuser", "user123")
	item, err := service.AddPet(ctx, user, Pet{Name: "重启恢复", Type: "CAT"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service = NewService(store)
	user = loginAs(t, service, "testuser", "user123")
	restored, err := service.GetPet(ctx, user, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Name != "重启恢复" {
		t.Fatalf("restored=%+v", restored)
	}
}

func TestCapacityRoomRemainsBookableUntilCurrentOccupancyIsFull(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	room, err := service.AddRoom(ctx, admin, Room{Number: "CAP-2", Type: "DELUXE", Status: "AVAILABLE", PricePerDay: 150, Capacity: 2})
	if err != nil {
		t.Fatal(err)
	}
	petOne, err := service.AddPet(ctx, user, Pet{Name: "小满", Type: "DOG"})
	if err != nil {
		t.Fatal(err)
	}
	petTwo, err := service.AddPet(ctx, user, Pet{Name: "团团", Type: "CAT"})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 2, 8, 0, 0, 0, time.UTC)
	first, err := service.CreateOrder(ctx, user, CreateOrderInput{PetID: petOne.ID, RoomID: room.ID, StartTime: start, EndTime: start.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"CONFIRMED", "IN_PROGRESS"} {
		if err := service.UpdateOrderStatus(ctx, admin, first.ID, state); err != nil {
			t.Fatal(err)
		}
	}
	available, err := service.AvailableRooms(ctx, user, "DELUXE")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range available {
		if item.ID == room.ID {
			found = true
			if item.CurrentOccupancy != 1 || item.Capacity != 2 {
				t.Fatalf("room occupancy=%d capacity=%d", item.CurrentOccupancy, item.Capacity)
			}
		}
	}
	if !found {
		t.Fatal("capacity room disappeared after its first active order")
	}
	second, err := service.CreateOrder(ctx, user, CreateOrderInput{PetID: petTwo.ID, RoomID: room.ID, StartTime: start, EndTime: start.Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("second booking within capacity failed: %v", err)
	}
	if err := service.UpdateOrderStatus(ctx, admin, first.ID, "COMPLETED"); err != nil {
		t.Fatal(err)
	}
	roomAfterCompletion, err := service.GetRoom(ctx, admin, room.ID)
	if err != nil {
		t.Fatal(err)
	}
	if roomAfterCompletion.Status != "AVAILABLE" {
		t.Fatalf("one order completion changed shared room status to %q", roomAfterCompletion.Status)
	}
	if second.Status != "PENDING" {
		t.Fatalf("second order status = %q", second.Status)
	}
}

func TestDuplicateServiceSelectionIsRejectedWithoutCreatingOrder(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	user := loginAs(t, service, "testuser", "user123")
	petItem, err := service.AddPet(ctx, user, Pet{Name: "重复服务", Type: "DOG"})
	if err != nil {
		t.Fatal(err)
	}
	rooms, _ := service.AvailableRooms(ctx, user, "STANDARD")
	services, _ := service.AvailableServices(ctx, user)
	start := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	_, err = service.CreateOrder(ctx, user, CreateOrderInput{
		PetID: petItem.ID, RoomID: rooms[0].ID, StartTime: start, EndTime: start.Add(24 * time.Hour),
		Services: []OrderService{{ServiceID: services[0].ID, Quantity: 1}, {ServiceID: services[0].ID, Quantity: 2}},
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("duplicate service error = %v", err)
	}
	page, err := service.ListOrders(ctx, user, 1, 10, "", "", "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 0 {
		t.Fatalf("orders created after rejected request = %d", page.Total)
	}
}

func TestUserDirectoryRequiresAdminAndFiltersByPhone(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	user := loginAs(t, service, "testuser", "user123")
	if _, err := service.ListUsers(ctx, user, 1, 10, "", "", ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("regular user list error = %v", err)
	}
	admin := loginAs(t, service, "admin", "admin123")
	registered, err := service.Register(ctx, "phoneowner", "owner123", "13912345678", "")
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.ListUsers(ctx, admin, 1, 10, "", "123456", "USER")
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.List) != 1 || page.List[0].ID != registered.ID {
		t.Fatalf("phone filtered users = %+v", page)
	}
}

func TestAdminProfileEditPreservesEnabledStatusWhenOmitted(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	updated, err := service.UpdateUser(ctx, admin, User{ID: user.UserID, Username: user.Username, Phone: "13900001111"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != 1 {
		t.Fatalf("status=%d after omitted status update", updated.Status)
	}
	token, _, _, err := service.Login(ctx, "testuser", "user123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, token); err != nil {
		t.Fatalf("user disabled by profile edit: %v", err)
	}
}

func TestPetWithOrderHistoryCannotBeDeleted(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	user := loginAs(t, service, "testuser", "user123")
	petItem, err := service.AddPet(ctx, user, Pet{Name: "留档宠物", Type: "CAT"})
	if err != nil {
		t.Fatal(err)
	}
	rooms, _ := service.AvailableRooms(ctx, user, "STANDARD")
	start := time.Date(2026, 12, 1, 8, 0, 0, 0, time.UTC)
	if _, err := service.CreateOrder(ctx, user, CreateOrderInput{PetID: petItem.ID, RoomID: rooms[0].ID, StartTime: start, EndTime: start.Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := service.DeletePet(ctx, user, petItem.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete pet with history error = %v", err)
	}
	if _, err := service.GetPet(ctx, user, petItem.ID); err != nil {
		t.Fatalf("pet disappeared after rejected delete: %v", err)
	}
}

func TestDailyRecordDatesStayInsideActiveFosterPeriod(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	petItem, err := service.AddPet(ctx, user, Pet{Name: "记录边界", Type: "DOG"})
	if err != nil {
		t.Fatal(err)
	}
	rooms, _ := service.AvailableRooms(ctx, user, "STANDARD")
	start := time.Date(2026, 12, 10, 8, 0, 0, 0, time.UTC)
	order, err := service.CreateOrder(ctx, user, CreateOrderInput{PetID: petItem.ID, RoomID: rooms[0].ID, StartTime: start, EndTime: start.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"CONFIRMED", "IN_PROGRESS"} {
		if err := service.UpdateOrderStatus(ctx, admin, order.ID, state); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.AddRecord(ctx, admin, DailyRecord{OrderID: order.ID, RecordDate: start.Add(-24 * time.Hour), Diet: "正常"}); !errors.Is(err, ErrValidation) {
		t.Fatalf("out-of-range record error = %v", err)
	}
	record, err := service.AddRecord(ctx, admin, DailyRecord{OrderID: order.ID, RecordDate: start.Add(24 * time.Hour), Diet: "正常"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.UpdateOrderStatus(ctx, admin, order.ID, "COMPLETED"); err != nil {
		t.Fatal(err)
	}
	record.Diet = "事后改写"
	if _, err := service.UpdateRecord(ctx, admin, record); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("completed record update error = %v", err)
	}
	if _, err := service.ListRecords(ctx, admin, 1, 10, 0, 0, "2026-12-20", "2026-12-01"); !errors.Is(err, ErrValidation) {
		t.Fatalf("reversed date range error = %v", err)
	}
}

func TestOrderServiceDailyPricingAndDetailName(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	user := loginAs(t, service, "testuser", "user123")
	petItem, err := service.AddPet(ctx, user, Pet{Name: "价目测试", Type: "DOG"})
	if err != nil {
		t.Fatal(err)
	}
	rooms, err := service.AvailableRooms(ctx, user, "STANDARD")
	if err != nil || len(rooms) == 0 {
		t.Fatalf("rooms=%v err=%v", rooms, err)
	}
	services, err := service.AvailableServices(ctx, user)
	if err != nil || len(services) == 0 {
		t.Fatalf("services=%v err=%v", services, err)
	}
	start := time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)
	order, err := service.CreateOrder(ctx, user, CreateOrderInput{PetID: petItem.ID, RoomID: rooms[0].ID, StartTime: start, EndTime: start.Add(48 * time.Hour), Services: []OrderService{{ServiceID: services[0].ID, Quantity: 2}}})
	if err != nil {
		t.Fatal(err)
	}
	wantSubtotal := services[0].Price * 2 * 2
	if len(order.Services) != 1 || order.Services[0].Name != services[0].Name || order.Services[0].Subtotal != wantSubtotal {
		t.Fatalf("services=%+v want name=%q subtotal=%v", order.Services, services[0].Name, wantSubtotal)
	}
	wantTotal := rooms[0].PricePerDay*2 + wantSubtotal
	if order.TotalAmount != wantTotal {
		t.Fatalf("total=%v want=%v", order.TotalAmount, wantTotal)
	}
}

func TestOrdersCreatedAtSameInstantUseDistinctOrderNumbers(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	user := loginAs(t, service, "testuser", "user123")
	pets := make([]Pet, 2)
	for i := range pets {
		var err error
		pets[i], err = service.AddPet(ctx, user, Pet{Name: fmt.Sprintf("同刻订单%d", i), Type: "DOG"})
		if err != nil {
			t.Fatal(err)
		}
	}
	rooms, err := service.AvailableRooms(ctx, user, "STANDARD")
	if err != nil || len(rooms) < 2 {
		t.Fatalf("rooms=%v err=%v", rooms, err)
	}
	start := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	first, err := service.CreateOrder(ctx, user, CreateOrderInput{PetID: pets[0].ID, RoomID: rooms[0].ID, StartTime: start, EndTime: start.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.CreateOrder(ctx, user, CreateOrderInput{PetID: pets[1].ID, RoomID: rooms[1].ID, StartTime: start, EndTime: start.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if first.OrderNo == second.OrderNo {
		t.Fatalf("duplicate order number %q", first.OrderNo)
	}
}

package pet

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func annotationRequest(t *testing.T, service *Service, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	NewHandler(service).ServeHTTP(response, request)
	return response
}

func annotationToken(t *testing.T, service *Service, username, password string) string {
	t.Helper()
	token, _, _, err := service.Login(context.Background(), username, password)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func annotationOrder(t *testing.T, service *Service, user Principal, capacity int, start time.Time, selected []OrderService) (FosterOrder, Room, Pet) {
	t.Helper()
	admin := loginAs(t, service, "admin", "admin123")
	room, err := service.AddRoom(context.Background(), admin, Room{
		Number: "ANN-" + strings.ReplaceAll(t.Name(), "/", "-"), Type: "STANDARD", Status: "AVAILABLE", PricePerDay: 100, Capacity: capacity,
	})
	if err != nil {
		t.Fatal(err)
	}
	petItem, err := service.AddPet(context.Background(), user, Pet{Name: "标注宠物", Type: "DOG"})
	if err != nil {
		t.Fatal(err)
	}
	order, err := service.CreateOrder(context.Background(), user, CreateOrderInput{
		PetID: petItem.ID, RoomID: room.ID, StartTime: start, EndTime: start.Add(72 * time.Hour), Services: selected,
	})
	if err != nil {
		t.Fatal(err)
	}
	return order, room, petItem
}

func annotationStart() time.Time {
	return time.Date(2027, 1, 10, 8, 0, 0, 0, time.UTC)
}

func TestAnnotationPartialProfileEditKeepsEnabled(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	updated, err := service.UpdateUser(ctx, admin, User{ID: user.UserID, Username: user.Username, Phone: "13800000000"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != 1 {
		t.Fatalf("status=%d", updated.Status)
	}
}

func TestAnnotationDuplicateRegistrationConflict(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	if _, err := service.Register(context.Background(), "sameowner", "owner123", "", ""); err != nil {
		t.Fatal(err)
	}
	_, err := service.Register(context.Background(), "sameowner", "different123", "", "")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate registration error=%v", err)
	}
	if _, _, _, err := service.Login(context.Background(), "sameowner", "owner123"); err != nil {
		t.Fatalf("original credentials changed: %v", err)
	}
}

func TestAnnotationDisabledAccountSessionRejected(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	token, user, _, err := service.Login(ctx, "testuser", "user123")
	if err != nil {
		t.Fatal(err)
	}
	admin := loginAs(t, service, "admin", "admin123")
	user.Status = 0
	if _, err := service.UpdateUser(ctx, admin, user); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("disabled user token error=%v", err)
	}
}

func TestAnnotationPasswordChangeRevokesSessions(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	first := annotationToken(t, service, "testuser", "user123")
	second := annotationToken(t, service, "testuser", "user123")
	principal, err := service.Authenticate(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ChangePassword(ctx, principal, "user123", "changed123"); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{first, second} {
		if _, err := service.Authenticate(ctx, token); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("old token remains valid: %v", err)
		}
	}
}

func TestAnnotationAdminResetRevokesSessions(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	token, user, _, err := service.Login(ctx, "testuser", "user123")
	if err != nil {
		t.Fatal(err)
	}
	admin := loginAs(t, service, "admin", "admin123")
	if err := service.ResetPassword(ctx, admin, user.ID, "reset123"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("token after reset error=%v", err)
	}
}

func TestAnnotationTrailingJSONRejected(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	response := annotationRequest(t, service, http.MethodPost, "/api/user/login", "", `{"username":"testuser","password":"user123"}{}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAnnotationErrorEnvelopeKeepsRequestID(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	request := httptest.NewRequest(http.MethodPost, "/api/user/login", bytes.NewBufferString(`{"username":""}`))
	request.Header.Set("X-Request-ID", "annotation-request-7")
	response := httptest.NewRecorder()
	NewHandler(service).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"requestId":"annotation-request-7"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAnnotationUserDirectoryRequiresAdmin(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	user := loginAs(t, service, "testuser", "user123")
	if _, err := service.ListUsers(context.Background(), user, 1, 10, "", "", ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("list users error=%v", err)
	}
}

func TestAnnotationPhoneFilterApplied(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	wanted, err := service.Register(ctx, "phonewanted", "owner123", "13912345678", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Register(ctx, "phoneother", "owner123", "13700001111", ""); err != nil {
		t.Fatal(err)
	}
	page, err := service.ListUsers(ctx, admin, 1, 10, "", "123456", "USER")
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.List) != 1 || page.List[0].ID != wanted.ID {
		t.Fatalf("page=%+v", page)
	}
}

func TestAnnotationMalformedPathIDRejected(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	token := annotationToken(t, service, "testuser", "user123")
	response := annotationRequest(t, service, http.MethodGet, "/api/pet/not-a-number", token, "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAnnotationMissingPetOwnerConflict(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	token := annotationToken(t, service, "admin", "admin123")
	response := annotationRequest(t, service, http.MethodPost, "/api/pet/add", token, `{"petName":"无主宠物","petType":"CAT","ownerId":999999}`)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAnnotationCustomerCannotChoosePetOwner(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	user := loginAs(t, service, "testuser", "user123")
	admin := loginAs(t, service, "admin", "admin123")
	petItem, err := service.AddPet(ctx, user, Pet{Name: "归属测试", Type: "DOG", OwnerID: admin.UserID})
	if err != nil {
		t.Fatal(err)
	}
	if petItem.OwnerID != user.UserID {
		t.Fatalf("owner=%d want=%d", petItem.OwnerID, user.UserID)
	}
}

func TestAnnotationPetWithOrderHistoryCannotBeDeleted(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	user := loginAs(t, service, "testuser", "user123")
	_, _, petItem := annotationOrder(t, service, user, 1, annotationStart(), nil)
	if err := service.DeletePet(context.Background(), user, petItem.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete error=%v", err)
	}
}

func TestAnnotationPendingBookingCountsTowardOccupancy(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	user := loginAs(t, service, "testuser", "user123")
	_, room, _ := annotationOrder(t, service, user, 2, annotationStart(), nil)
	reloaded, err := service.GetRoom(context.Background(), user, room.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.CurrentOccupancy != 1 {
		t.Fatalf("occupancy=%d", reloaded.CurrentOccupancy)
	}
}

func TestAnnotationReservedRoomCannotBeBooked(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	room, err := service.AddRoom(ctx, admin, Room{Number: "RESERVED-15", Type: "VIP", Status: "RESERVED", PricePerDay: 200, Capacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	petItem, err := service.AddPet(ctx, user, Pet{Name: "留房测试", Type: "CAT"})
	if err != nil {
		t.Fatal(err)
	}
	available, err := service.AvailableRooms(ctx, user, "VIP")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range available {
		if item.ID == room.ID {
			t.Fatal("reserved room listed as available")
		}
	}
	_, err = service.CreateOrder(ctx, user, CreateOrderInput{PetID: petItem.ID, RoomID: room.ID, StartTime: annotationStart(), EndTime: annotationStart().Add(24 * time.Hour)})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("create error=%v", err)
	}
}

func TestAnnotationConfirmedBookingBlocksCapacity(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	first, room, _ := annotationOrder(t, service, user, 1, annotationStart(), nil)
	if err := service.UpdateOrderStatus(ctx, admin, first.ID, "CONFIRMED"); err != nil {
		t.Fatal(err)
	}
	secondPet, err := service.AddPet(ctx, user, Pet{Name: "第二只", Type: "DOG"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.CreateOrder(ctx, user, CreateOrderInput{PetID: secondPet.ID, RoomID: room.ID, StartTime: annotationStart(), EndTime: annotationStart().Add(24 * time.Hour)})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("second order error=%v", err)
	}
}

func TestAnnotationCancelledContextStopsOrderCreation(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	room, err := service.AddRoom(ctx, admin, Room{Number: "CTX-17", Type: "STANDARD", Status: "AVAILABLE", PricePerDay: 100, Capacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	petItem, err := service.AddPet(ctx, user, Pet{Name: "取消请求", Type: "DOG"})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = service.CreateOrder(cancelled, user, CreateOrderInput{PetID: petItem.ID, RoomID: room.ID, StartTime: annotationStart(), EndTime: annotationStart().Add(24 * time.Hour)})
	if err == nil {
		t.Fatal("cancelled request created an order")
	}
}

func TestAnnotationSharedRoomCompletionKeepsRoomAvailable(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	first, room, _ := annotationOrder(t, service, user, 2, annotationStart(), nil)
	secondPet, err := service.AddPet(ctx, user, Pet{Name: "共享房第二只", Type: "CAT"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.CreateOrder(ctx, user, CreateOrderInput{PetID: secondPet.ID, RoomID: room.ID, StartTime: annotationStart(), EndTime: annotationStart().Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for _, order := range []FosterOrder{first, second} {
		for _, state := range []string{"CONFIRMED", "IN_PROGRESS"} {
			if err := service.UpdateOrderStatus(ctx, admin, order.ID, state); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := service.UpdateOrderStatus(ctx, admin, first.ID, "COMPLETED"); err != nil {
		t.Fatal(err)
	}
	reloaded, err := service.GetRoom(ctx, admin, room.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Status != "AVAILABLE" || reloaded.CurrentOccupancy != 1 {
		t.Fatalf("room=%+v", reloaded)
	}
}

func TestAnnotationCapacityCannotShrinkBelowActiveOrders(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	_, room, _ := annotationOrder(t, service, user, 2, annotationStart(), nil)
	secondPet, _ := service.AddPet(ctx, user, Pet{Name: "缩容第二只", Type: "CAT"})
	if _, err := service.CreateOrder(ctx, user, CreateOrderInput{PetID: secondPet.ID, RoomID: room.ID, StartTime: annotationStart(), EndTime: annotationStart().Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	room.Capacity = 1
	if _, err := service.UpdateRoom(ctx, admin, room); !errors.Is(err, ErrConflict) {
		t.Fatalf("shrink error=%v", err)
	}
}

func TestAnnotationUsedServiceDeleteReturnsConflict(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	items, err := service.AvailableServices(ctx, user)
	if err != nil || len(items) == 0 {
		t.Fatalf("services=%v err=%v", items, err)
	}
	annotationOrder(t, service, user, 1, annotationStart(), []OrderService{{ServiceID: items[0].ID}})
	if err := service.DeleteServiceItem(ctx, admin, items[0].ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete service error=%v", err)
	}
}

func TestAnnotationInactiveServiceRejected(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	item, err := service.AddServiceItem(ctx, admin, ServiceItem{Name: "停用护理", Price: 30, Status: 0})
	if err != nil {
		t.Fatal(err)
	}
	room, _ := service.AddRoom(ctx, admin, Room{Number: "SVC-21", Type: "STANDARD", Status: "AVAILABLE", PricePerDay: 100, Capacity: 1})
	petItem, _ := service.AddPet(ctx, user, Pet{Name: "服务状态", Type: "DOG"})
	_, err = service.CreateOrder(ctx, user, CreateOrderInput{PetID: petItem.ID, RoomID: room.ID, StartTime: annotationStart(), EndTime: annotationStart().Add(24 * time.Hour), Services: []OrderService{{ServiceID: item.ID, Quantity: 1}}})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("inactive service error=%v", err)
	}
}

func TestAnnotationDuplicateServiceSelectionValidation(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	items, _ := service.AvailableServices(ctx, user)
	room, _ := service.AddRoom(ctx, admin, Room{Number: "DUP-22", Type: "STANDARD", Status: "AVAILABLE", PricePerDay: 100, Capacity: 1})
	petItem, _ := service.AddPet(ctx, user, Pet{Name: "重复服务", Type: "DOG"})
	_, err := service.CreateOrder(ctx, user, CreateOrderInput{PetID: petItem.ID, RoomID: room.ID, StartTime: annotationStart(), EndTime: annotationStart().Add(24 * time.Hour), Services: []OrderService{{ServiceID: items[0].ID}, {ServiceID: items[0].ID}}})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("duplicate service error=%v", err)
	}
}

func TestAnnotationServiceSubtotalUsesStayDays(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	user := loginAs(t, service, "testuser", "user123")
	items, _ := service.AvailableServices(ctx, user)
	order, _, _ := annotationOrder(t, service, user, 1, annotationStart(), []OrderService{{ServiceID: items[0].ID, Quantity: 2}})
	want := items[0].Price * 2 * 3
	if len(order.Services) != 1 || order.Services[0].Subtotal != want {
		t.Fatalf("services=%+v want=%v", order.Services, want)
	}
}

func TestAnnotationOrderDetailIncludesServiceName(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	user := loginAs(t, service, "testuser", "user123")
	items, _ := service.AvailableServices(ctx, user)
	order, _, _ := annotationOrder(t, service, user, 1, annotationStart(), []OrderService{{ServiceID: items[0].ID}})
	detail, err := service.GetOrder(ctx, user, order.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.Services) != 1 || detail.Services[0].Name != items[0].Name {
		t.Fatalf("services=%+v", detail.Services)
	}
}

func TestAnnotationSameInstantOrderNumbersUnique(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	orders := make([]FosterOrder, 2)
	for index := range orders {
		room, _ := service.AddRoom(ctx, admin, Room{Number: "NO-25-" + string(rune('A'+index)), Type: "STANDARD", Status: "AVAILABLE", PricePerDay: 100, Capacity: 1})
		petItem, _ := service.AddPet(ctx, user, Pet{Name: "同刻单号" + string(rune('A'+index)), Type: "DOG"})
		var err error
		orders[index], err = service.CreateOrder(ctx, user, CreateOrderInput{PetID: petItem.ID, RoomID: room.ID, StartTime: annotationStart(), EndTime: annotationStart().Add(24 * time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
	}
	if orders[0].OrderNo == orders[1].OrderNo {
		t.Fatalf("duplicate order number=%s", orders[0].OrderNo)
	}
}

func TestAnnotationOnlyAdminTransitionsOrderStatus(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	user := loginAs(t, service, "testuser", "user123")
	order, _, _ := annotationOrder(t, service, user, 1, annotationStart(), nil)
	if err := service.UpdateOrderStatus(context.Background(), user, order.ID, "CONFIRMED"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("transition error=%v", err)
	}
}

func TestAnnotationRecordDateInsideFosterPeriod(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	order, _, _ := annotationOrder(t, service, user, 1, annotationStart(), nil)
	for _, state := range []string{"CONFIRMED", "IN_PROGRESS"} {
		if err := service.UpdateOrderStatus(ctx, admin, order.ID, state); err != nil {
			t.Fatal(err)
		}
	}
	_, err := service.AddRecord(ctx, admin, DailyRecord{OrderID: order.ID, RecordDate: annotationStart().Add(-24 * time.Hour), Diet: "正常"})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("record error=%v", err)
	}
}

func TestAnnotationCompletedRecordImmutable(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	order, _, _ := annotationOrder(t, service, user, 1, annotationStart(), nil)
	for _, state := range []string{"CONFIRMED", "IN_PROGRESS"} {
		if err := service.UpdateOrderStatus(ctx, admin, order.ID, state); err != nil {
			t.Fatal(err)
		}
	}
	record, err := service.AddRecord(ctx, admin, DailyRecord{OrderID: order.ID, RecordDate: annotationStart(), Diet: "正常"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.UpdateOrderStatus(ctx, admin, order.ID, "COMPLETED"); err != nil {
		t.Fatal(err)
	}
	record.Diet = "覆盖"
	if _, err := service.UpdateRecord(ctx, admin, record); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("update error=%v", err)
	}
}

func TestAnnotationInvalidRecordDateFilterRejected(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	admin := loginAs(t, service, "admin", "admin123")
	if _, err := service.ListRecords(context.Background(), admin, 1, 10, 0, 0, "2027/01/01", ""); !errors.Is(err, ErrValidation) {
		t.Fatalf("filter error=%v", err)
	}
}

func TestAnnotationDuplicateRecordReturnsConflict(t *testing.T) {
	service, closeStore := testService(t)
	defer closeStore()
	ctx := context.Background()
	admin := loginAs(t, service, "admin", "admin123")
	user := loginAs(t, service, "testuser", "user123")
	order, _, _ := annotationOrder(t, service, user, 1, annotationStart(), nil)
	for _, state := range []string{"CONFIRMED", "IN_PROGRESS"} {
		if err := service.UpdateOrderStatus(ctx, admin, order.ID, state); err != nil {
			t.Fatal(err)
		}
	}
	input := DailyRecord{OrderID: order.ID, RecordDate: annotationStart(), Diet: "正常"}
	if _, err := service.AddRecord(ctx, admin, input); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AddRecord(ctx, admin, input); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate record error=%v", err)
	}
}

package pet

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func (s *Service) AddRoom(ctx context.Context, principal Principal, input Room) (Room, error) {
	if principal.Role != RoleAdmin {
		return Room{}, ErrForbidden
	}
	if strings.TrimSpace(input.Number) == "" || strings.TrimSpace(input.Type) == "" {
		return Room{}, fmt.Errorf("%w: room number and type are required", ErrValidation)
	}
	if input.PricePerDay < 0 {
		return Room{}, fmt.Errorf("%w: room price cannot be negative", ErrValidation)
	}
	if input.Capacity < 1 {
		input.Capacity = 1
	}
	if input.Status == "" {
		input.Status = "AVAILABLE"
	}
	if !validRoomStatus(input.Status) {
		return Room{}, fmt.Errorf("%w: invalid room status", ErrValidation)
	}
	now := formatStoredTime(s.now())
	result, err := s.store.db.ExecContext(ctx, `INSERT INTO rooms(room_number,room_type,status,price_per_day,description,capacity,create_time,update_time) VALUES(?,?,?,?,?,?,?,?)`, input.Number, input.Type, input.Status, input.PricePerDay, input.Description, input.Capacity, now, now)
	if err != nil {
		return Room{}, translateServiceError(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Room{}, err
	}
	return s.GetRoom(ctx, principal, id)
}
func (s *Service) UpdateRoom(ctx context.Context, principal Principal, input Room) (Room, error) {
	if principal.Role != RoleAdmin {
		return Room{}, ErrForbidden
	}
	if input.ID == 0 || strings.TrimSpace(input.Number) == "" || strings.TrimSpace(input.Type) == "" {
		return Room{}, fmt.Errorf("%w: room id, number and type are required", ErrValidation)
	}
	if input.Capacity < 1 || input.PricePerDay < 0 || !validRoomStatus(input.Status) {
		return Room{}, fmt.Errorf("%w: invalid room capacity, price or status", ErrValidation)
	}
	var active int
	if err := s.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM foster_orders WHERE room_id=? AND status IN ('PENDING','CONFIRMED','IN_PROGRESS')`, input.ID).Scan(&active); err != nil {
		return Room{}, err
	}
	if input.Capacity < active || (input.Status == "CLEANING" && active > 0) {
		return Room{}, fmt.Errorf("%w: room has active foster orders", ErrConflict)
	}
	result, err := s.store.db.ExecContext(ctx, `UPDATE rooms SET room_number=?,room_type=?,status=?,price_per_day=?,description=?,capacity=?,update_time=? WHERE room_id=?`, strings.TrimSpace(input.Number), strings.TrimSpace(input.Type), input.Status, input.PricePerDay, input.Description, input.Capacity, formatStoredTime(s.now()), input.ID)
	if err != nil {
		return Room{}, translateServiceError(err)
	}
	if err := requireAffected(result, ErrNotFound); err != nil {
		return Room{}, err
	}
	return s.GetRoom(ctx, principal, input.ID)
}
func (s *Service) DeleteRoom(ctx context.Context, principal Principal, id int64) error {
	if principal.Role != RoleAdmin {
		return ErrForbidden
	}
	var orders int
	if err := s.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM foster_orders WHERE room_id=?`, id).Scan(&orders); err != nil {
		return err
	}
	if orders > 0 {
		return fmt.Errorf("%w: room has foster order history", ErrConflict)
	}
	result, err := s.store.db.ExecContext(ctx, `DELETE FROM rooms WHERE room_id=?`, id)
	if err != nil {
		return translateServiceError(err)
	}
	return requireAffected(result, ErrNotFound)
}
func (s *Service) GetRoom(ctx context.Context, principal Principal, id int64) (Room, error) {
	if principal.UserID == 0 {
		return Room{}, ErrUnauthenticated
	}
	var item Room
	var created, updated string
	err := s.store.db.QueryRowContext(ctx, `SELECT r.room_id,r.room_number,r.room_type,r.status,r.price_per_day,COALESCE(r.description,''),r.capacity,
		(SELECT COUNT(*) FROM foster_orders o WHERE o.room_id=r.room_id AND o.status IN ('PENDING','CONFIRMED','IN_PROGRESS')),r.create_time,r.update_time
		FROM rooms r WHERE r.room_id=?`, id).Scan(&item.ID, &item.Number, &item.Type, &item.Status, &item.PricePerDay, &item.Description, &item.Capacity, &item.CurrentOccupancy, &created, &updated)
	if err == sql.ErrNoRows {
		return Room{}, ErrNotFound
	}
	if err != nil {
		return Room{}, err
	}
	item.CreatedAt, _ = parseStoredTime(created)
	item.UpdatedAt, _ = parseStoredTime(updated)
	return item, nil
}
func (s *Service) UpdateRoomStatus(ctx context.Context, principal Principal, id int64, status string) error {
	if principal.Role != RoleAdmin {
		return ErrForbidden
	}
	if !validRoomStatus(status) {
		return fmt.Errorf("%w: invalid room status", ErrValidation)
	}
	if status != "AVAILABLE" {
		var active int
		if err := s.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM foster_orders WHERE room_id=? AND status IN ('PENDING','CONFIRMED','IN_PROGRESS')`, id).Scan(&active); err != nil {
			return err
		}
		if active > 0 {
			return fmt.Errorf("%w: room has active foster orders", ErrConflict)
		}
	}
	result, err := s.store.db.ExecContext(ctx, `UPDATE rooms SET status=?,update_time=? WHERE room_id=?`, status, formatStoredTime(s.now()), id)
	if err != nil {
		return err
	}
	return requireAffected(result, ErrNotFound)
}
func validRoomStatus(status string) bool {
	switch status {
	case "AVAILABLE", "RESERVED", "OCCUPIED", "CLEANING":
		return true
	default:
		return false
	}
}
func (s *Service) ListRooms(ctx context.Context, principal Principal, pageNum, pageSize int, number, typ, status string) (Page[Room], error) {
	if principal.UserID == 0 {
		return Page[Room]{}, ErrUnauthenticated
	}
	pageNum, pageSize = normalizePage(pageNum, pageSize)
	where := []string{"1=1"}
	args := []any{}
	if number != "" {
		where = append(where, "room_number LIKE ?")
		args = append(args, "%"+number+"%")
	}
	if typ != "" {
		where = append(where, "room_type=?")
		args = append(args, typ)
	}
	if status != "" {
		where = append(where, "status=?")
		args = append(args, status)
	}
	clause := strings.Join(where, " AND ")
	var total int
	if err := s.store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM rooms WHERE "+clause, args...).Scan(&total); err != nil {
		return Page[Room]{}, err
	}
	rows, err := s.store.db.QueryContext(ctx, "SELECT r.room_id,r.room_number,r.room_type,r.status,r.price_per_day,COALESCE(r.description,''),r.capacity,(SELECT COUNT(*) FROM foster_orders o WHERE o.room_id=r.room_id AND o.status IN ('PENDING','CONFIRMED','IN_PROGRESS')),r.create_time,r.update_time FROM rooms r WHERE "+clause+" ORDER BY r.room_id DESC LIMIT ? OFFSET ?", append(args, pageSize, (pageNum-1)*pageSize)...)
	if err != nil {
		return Page[Room]{}, err
	}
	defer rows.Close()
	items := make([]Room, 0)
	for rows.Next() {
		var item Room
		var created, updated string
		if err := rows.Scan(&item.ID, &item.Number, &item.Type, &item.Status, &item.PricePerDay, &item.Description, &item.Capacity, &item.CurrentOccupancy, &created, &updated); err != nil {
			return Page[Room]{}, err
		}
		item.CreatedAt, _ = parseStoredTime(created)
		item.UpdatedAt, _ = parseStoredTime(updated)
		items = append(items, item)
	}
	return Page[Room]{List: items, Total: total, PageNum: pageNum, PageSize: pageSize}, rows.Err()
}
func (s *Service) AvailableRooms(ctx context.Context, principal Principal, typ string) ([]Room, error) {
	page, err := s.ListRooms(ctx, principal, 1, 100, "", typ, "")
	if err != nil {
		return nil, err
	}
	rooms := make([]Room, 0, len(page.List))
	for _, room := range page.List {
		if room.Status == "AVAILABLE" && room.CurrentOccupancy < room.Capacity {
			rooms = append(rooms, room)
		}
	}
	return rooms, nil
}

func (s *Service) AddServiceItem(ctx context.Context, principal Principal, input ServiceItem) (ServiceItem, error) {
	if principal.Role != RoleAdmin {
		return ServiceItem{}, ErrForbidden
	}
	if strings.TrimSpace(input.Name) == "" || input.Price < 0 || (input.Status != 0 && input.Status != 1) {
		return ServiceItem{}, fmt.Errorf("%w: service name is required", ErrValidation)
	}
	now := formatStoredTime(s.now())
	result, err := s.store.db.ExecContext(ctx, `INSERT INTO service_items(service_name,description,price,status,create_time,update_time) VALUES(?,?,?,?,?,?)`, input.Name, input.Description, input.Price, input.Status, now, now)
	if err != nil {
		return ServiceItem{}, translateServiceError(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return ServiceItem{}, err
	}
	return s.GetServiceItem(ctx, principal, id)
}
func (s *Service) UpdateServiceItem(ctx context.Context, principal Principal, input ServiceItem) (ServiceItem, error) {
	if principal.Role != RoleAdmin {
		return ServiceItem{}, ErrForbidden
	}
	if input.ID == 0 || strings.TrimSpace(input.Name) == "" || input.Price < 0 || (input.Status != 0 && input.Status != 1) {
		return ServiceItem{}, fmt.Errorf("%w: valid service id, name, price and status are required", ErrValidation)
	}
	result, err := s.store.db.ExecContext(ctx, `UPDATE service_items SET service_name=?,description=?,price=?,status=?,update_time=? WHERE service_id=?`, input.Name, input.Description, input.Price, input.Status, formatStoredTime(s.now()), input.ID)
	if err != nil {
		return ServiceItem{}, translateServiceError(err)
	}
	if err := requireAffected(result, ErrNotFound); err != nil {
		return ServiceItem{}, err
	}
	return s.GetServiceItem(ctx, principal, input.ID)
}
func (s *Service) DeleteServiceItem(ctx context.Context, principal Principal, id int64) error {
	if principal.Role != RoleAdmin {
		return ErrForbidden
	}
	result, err := s.store.db.ExecContext(ctx, `DELETE FROM service_items WHERE service_id=?`, id)
	if err != nil {
		return translateServiceError(err)
	}
	return requireAffected(result, ErrNotFound)
}
func (s *Service) GetServiceItem(ctx context.Context, principal Principal, id int64) (ServiceItem, error) {
	if principal.UserID == 0 {
		return ServiceItem{}, ErrUnauthenticated
	}
	var item ServiceItem
	var created, updated string
	err := s.store.db.QueryRowContext(ctx, `SELECT service_id,service_name,COALESCE(description,''),price,status,create_time,update_time FROM service_items WHERE service_id=?`, id).Scan(&item.ID, &item.Name, &item.Description, &item.Price, &item.Status, &created, &updated)
	if err == sql.ErrNoRows {
		return ServiceItem{}, ErrNotFound
	}
	if err != nil {
		return ServiceItem{}, err
	}
	item.CreatedAt, _ = parseStoredTime(created)
	item.UpdatedAt, _ = parseStoredTime(updated)
	return item, nil
}
func (s *Service) ListServiceItems(ctx context.Context, principal Principal, pageNum, pageSize int, name string, status *int) (Page[ServiceItem], error) {
	if principal.UserID == 0 {
		return Page[ServiceItem]{}, ErrUnauthenticated
	}
	pageNum, pageSize = normalizePage(pageNum, pageSize)
	where := []string{"1=1"}
	args := []any{}
	if name != "" {
		where = append(where, "service_name LIKE ?")
		args = append(args, "%"+name+"%")
	}
	if status != nil {
		where = append(where, "status=?")
		args = append(args, *status)
	}
	clause := strings.Join(where, " AND ")
	var total int
	if err := s.store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM service_items WHERE "+clause, args...).Scan(&total); err != nil {
		return Page[ServiceItem]{}, err
	}
	rows, err := s.store.db.QueryContext(ctx, "SELECT service_id,service_name,COALESCE(description,''),price,status,create_time,update_time FROM service_items WHERE "+clause+" ORDER BY service_id DESC LIMIT ? OFFSET ?", append(args, pageSize, (pageNum-1)*pageSize)...)
	if err != nil {
		return Page[ServiceItem]{}, err
	}
	defer rows.Close()
	items := make([]ServiceItem, 0)
	for rows.Next() {
		var item ServiceItem
		var created, updated string
		if err := rows.Scan(&item.ID, &item.Name, &item.Description, &item.Price, &item.Status, &created, &updated); err != nil {
			return Page[ServiceItem]{}, err
		}
		item.CreatedAt, _ = parseStoredTime(created)
		item.UpdatedAt, _ = parseStoredTime(updated)
		items = append(items, item)
	}
	return Page[ServiceItem]{List: items, Total: total, PageNum: pageNum, PageSize: pageSize}, rows.Err()
}
func (s *Service) AllServices(ctx context.Context, p Principal) ([]ServiceItem, error) {
	page, err := s.ListServiceItems(ctx, p, 1, 100, "", nil)
	return page.List, err
}
func (s *Service) AvailableServices(ctx context.Context, p Principal) ([]ServiceItem, error) {
	status := 1
	page, err := s.ListServiceItems(ctx, p, 1, 100, "", &status)
	return page.List, err
}

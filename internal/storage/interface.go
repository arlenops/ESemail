package storage

import (
	"fmt"
	"reflect"
	"time"
)

// Storage 存储接口定义
type Storage interface {
	Initialize() error
	Save(category, id string, data interface{}) error
	Load(category, id string, data interface{}) error
	Delete(category, id string) error
	List(category string) ([]string, error)
	Exists(category, id string) bool
	Backup(backupDir string) error
	Restore(backupDir string) error
	GetStats() (map[string]interface{}, error)
}

// Repository 通用仓储接口
type Repository[T any] interface {
	Create(entity *T) error
	GetByID(id string) (*T, error)
	Update(id string, entity *T) error
	Delete(id string) error
	List() ([]*T, error)
	Exists(id string) bool
}

// BaseEntity 基础实体结构
type BaseEntity struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GenericRepository 通用仓储实现
type GenericRepository[T any] struct {
	storage  Storage
	category string
}

// NewGenericRepository 创建通用仓储
func NewGenericRepository[T any](storage Storage, category string) *GenericRepository[T] {
	return &GenericRepository[T]{
		storage:  storage,
		category: category,
	}
}

// Create 创建实体
func (r *GenericRepository[T]) Create(entity *T) error {
	// 通过反射获取ID字段
	v := reflect.ValueOf(entity).Elem()
	idField := v.FieldByName("ID")
	if !idField.IsValid() {
		return fmt.Errorf("实体必须包含ID字段")
	}

	id := idField.String()
	if id == "" {
		return fmt.Errorf("实体ID不能为空")
	}

	// 检查是否已存在
	if r.storage.Exists(r.category, id) {
		return fmt.Errorf("实体已存在: %s", id)
	}

	// 设置创建时间和更新时间
	if createdAtField := v.FieldByName("CreatedAt"); createdAtField.IsValid() && createdAtField.CanSet() {
		createdAtField.Set(reflect.ValueOf(time.Now()))
	}
	if updatedAtField := v.FieldByName("UpdatedAt"); updatedAtField.IsValid() && updatedAtField.CanSet() {
		updatedAtField.Set(reflect.ValueOf(time.Now()))
	}

	return r.storage.Save(r.category, id, entity)
}

// GetByID 根据ID获取实体
func (r *GenericRepository[T]) GetByID(id string) (*T, error) {
	var entity T
	if err := r.storage.Load(r.category, id, &entity); err != nil {
		if err == ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &entity, nil
}

// Update 更新实体
func (r *GenericRepository[T]) Update(id string, entity *T) error {
	// 检查实体是否存在
	if !r.storage.Exists(r.category, id) {
		return fmt.Errorf("实体不存在: %s", id)
	}

	// 设置更新时间
	v := reflect.ValueOf(entity).Elem()
	if updatedAtField := v.FieldByName("UpdatedAt"); updatedAtField.IsValid() && updatedAtField.CanSet() {
		updatedAtField.Set(reflect.ValueOf(time.Now()))
	}

	return r.storage.Save(r.category, id, entity)
}

// Delete 删除实体
func (r *GenericRepository[T]) Delete(id string) error {
	return r.storage.Delete(r.category, id)
}

// List 列出所有实体
func (r *GenericRepository[T]) List() ([]*T, error) {
	ids, err := r.storage.List(r.category)
	if err != nil {
		return nil, err
	}

	var entities []*T
	for _, id := range ids {
		entity, err := r.GetByID(id)
		if err != nil {
			continue // 跳过无法加载的实体
		}
		if entity != nil {
			entities = append(entities, entity)
		}
	}

	return entities, nil
}

// Exists 检查实体是否存在
func (r *GenericRepository[T]) Exists(id string) bool {
	return r.storage.Exists(r.category, id)
}
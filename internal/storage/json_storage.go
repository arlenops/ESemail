package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"
)

// JSONStorage JSON文件存储实现
type JSONStorage struct {
	dataDir string
	mutex   sync.RWMutex
}

// NewJSONStorage 创建新的JSON存储实例
func NewJSONStorage(dataDir string) *JSONStorage {
	return &JSONStorage{
		dataDir: dataDir,
	}
}

// Initialize 初始化存储
func (s *JSONStorage) Initialize() error {
	// 创建数据目录
	if err := os.MkdirAll(s.dataDir, 0755); err != nil {
		return fmt.Errorf("创建数据目录失败: %v", err)
	}

	// 创建子目录
	subdirs := []string{"users", "domains", "config", "mail", "certificates", "logs"}
	for _, subdir := range subdirs {
		dir := filepath.Join(s.dataDir, subdir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建子目录 %s 失败: %v", subdir, err)
		}
	}

	return nil
}

// Save 保存数据到JSON文件
func (s *JSONStorage) Save(category, id string, data interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 构建文件路径
	dir := filepath.Join(s.dataDir, category)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	filename := fmt.Sprintf("%s.json", id)
	filePath := filepath.Join(dir, filename)

	// 将数据序列化为JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化数据失败: %v", err)
	}

	// 写入文件
	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	return nil
}

// Load 从JSON文件加载数据
func (s *JSONStorage) Load(category, id string, data interface{}) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	filename := fmt.Sprintf("%s.json", id)
	filePath := filepath.Join(s.dataDir, category, filename)

	// 读取文件
	jsonData, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return fmt.Errorf("读取文件失败: %v", err)
	}

	// 反序列化JSON数据
	if err := json.Unmarshal(jsonData, data); err != nil {
		return fmt.Errorf("反序列化数据失败: %v", err)
	}

	return nil
}

// Delete 删除数据文件
func (s *JSONStorage) Delete(category, id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	filename := fmt.Sprintf("%s.json", id)
	filePath := filepath.Join(s.dataDir, category, filename)

	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return fmt.Errorf("删除文件失败: %v", err)
	}

	return nil
}

// List 列出指定类别的所有数据
func (s *JSONStorage) List(category string) ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	dir := filepath.Join(s.dataDir, category)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("读取目录失败: %v", err)
	}

	var ids []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			id := entry.Name()[:len(entry.Name())-5] // 移除.json扩展名
			ids = append(ids, id)
		}
	}

	return ids, nil
}

// LoadAll 加载指定类别的所有数据
func (s *JSONStorage) LoadAll(category string, dataType interface{}) ([]interface{}, error) {
	ids, err := s.List(category)
	if err != nil {
		return nil, err
	}

	var results []interface{}
	for _, id := range ids {
		// 创建数据类型的新实例
		data := reflect.New(reflect.TypeOf(dataType).Elem()).Interface()
		if err := s.Load(category, id, data); err != nil {
			continue // 跳过无法加载的文件
		}
		results = append(results, data)
	}

	return results, nil
}

// Exists 检查数据是否存在
func (s *JSONStorage) Exists(category, id string) bool {
	filename := fmt.Sprintf("%s.json", id)
	filePath := filepath.Join(s.dataDir, category, filename)
	
	_, err := os.Stat(filePath)
	return err == nil
}

// Backup 备份数据
func (s *JSONStorage) Backup(backupDir string) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	timestamp := time.Now().Format("20060102_150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("backup_%s", timestamp))

	if err := os.MkdirAll(backupPath, 0755); err != nil {
		return fmt.Errorf("创建备份目录失败: %v", err)
	}

	// 复制整个数据目录
	return s.copyDir(s.dataDir, backupPath)
}

// copyDir 递归复制目录
func (s *JSONStorage) copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// 计算目标路径
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, relPath)

		if d.IsDir() {
			return os.MkdirAll(dstPath, d.Type())
		}

		// 复制文件
		srcFile, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		return os.WriteFile(dstPath, srcFile, 0644)
	})
}

// Restore 恢复数据
func (s *JSONStorage) Restore(backupDir string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 检查备份目录是否存在
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		return fmt.Errorf("备份目录不存在: %s", backupDir)
	}

	// 备份当前数据
	currentBackup := filepath.Join(s.dataDir, "..", "current_backup")
	if err := s.copyDir(s.dataDir, currentBackup); err != nil {
		return fmt.Errorf("备份当前数据失败: %v", err)
	}

	// 删除当前数据目录
	if err := os.RemoveAll(s.dataDir); err != nil {
		return fmt.Errorf("删除当前数据失败: %v", err)
	}

	// 恢复数据
	if err := s.copyDir(backupDir, s.dataDir); err != nil {
		// 恢复失败，尝试恢复原数据
		s.copyDir(currentBackup, s.dataDir)
		return fmt.Errorf("恢复数据失败: %v", err)
	}

	// 删除临时备份
	os.RemoveAll(currentBackup)

	return nil
}

// GetStats 获取存储统计信息
func (s *JSONStorage) GetStats() (map[string]interface{}, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	stats := make(map[string]interface{})
	
	// 统计各类别的文件数量
	categories := []string{"users", "domains", "config", "mail", "certificates", "logs"}
	totalFiles := 0
	totalSize := int64(0)

	for _, category := range categories {
		dir := filepath.Join(s.dataDir, category)
		count := 0
		categorySize := int64(0)

		filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !d.IsDir() {
				count++
				if info, err := d.Info(); err == nil {
					categorySize += info.Size()
				}
			}
			return nil
		})

		stats[category] = map[string]interface{}{
			"count": count,
			"size":  categorySize,
		}
		totalFiles += count
		totalSize += categorySize
	}

	stats["total"] = map[string]interface{}{
		"files": totalFiles,
		"size":  totalSize,
	}

	return stats, nil
}

// 常用的错误定义
var (
	ErrNotFound    = errors.New("数据不存在")
	ErrInvalidData = errors.New("无效的数据格式")
)
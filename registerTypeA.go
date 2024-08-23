package auth

import (
	"errors"
	"strings"

	"github.com/lib/pq"
	"gorm.io/gorm"
)

// Register function to handle the registration and error handling
func Register(request interface{}, con *gorm.DB) ([]string, error) {
	result := con.Create(request)

	if result.Error != nil {
		if isDuplicateKeyError(result.Error) {
			errorMsg := result.Error.Error()
			duplicateKey := extractDuplicateKeys(errorMsg)

			return duplicateKey, nil
		}
		return nil, errors.New("ระบบขัดข้อง กรุณาติดต่อผู้ดูแลระบบ")
	}

	return nil, nil
}

// isDuplicateKeyError checks if the error is a duplicate key error
func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	// Check if the error is related to duplicate key (PostgreSQL example)
	if pqErr, ok := err.(*pq.Error); ok {
		return pqErr.Code == "23505"
	}
	return false
}

// extractDuplicateKeys extracts duplicate keys from PostgreSQL error message
func extractDuplicateKeys(errorMsg string) []string {
	keys := []string{}
	// PostgreSQL error message example:
	// ERROR: duplicate key value violates unique constraint "table_name_column_name_key"
	if strings.Contains(errorMsg, "violates unique constraint") {
		parts := strings.Split(errorMsg, "violates unique constraint")
		if len(parts) > 1 {
			constraintPart := parts[1]
			// Extract constraint name, it should be in quotes or underscores
			start := strings.Index(constraintPart, `"`)
			end := strings.LastIndex(constraintPart, `"`)
			if start > 0 && end > start {
				constraintName := constraintPart[start+1 : end]
				// Remove the prefix "table_name_" to get the column name
				constraintParts := strings.Split(constraintName, "_")
				if len(constraintParts) > 1 {
					columnName := constraintParts[len(constraintParts)-1]
					keys = append(keys, columnName)
				}
			}
		}
	}
	return keys
}

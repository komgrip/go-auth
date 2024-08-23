package auth

import (
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Token struct {
	AccessToken  string
	RefreshToken string
}

type LoginRequest struct {
	Username string
	Password string
	Con      *gorm.DB
}

type User struct {
	ID                int
	UserName          string
	Password          string
	StatusID          int
	RoleID            int
	PermissionGroupID int
}

// Login ด้วย username และ password
func LoginTypeA(request LoginRequest) (User, Token, error) {
	user, err := GetUserByUserName(request)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return User{}, Token{}, errors.New("ชื่อผู้ใช้งานไม่ถูกต้อง กรุณาระบุใหม่อีกครั้ง")
		} else {
			return User{}, Token{}, errors.New("ระบบขัดข้อง กรุณาติดต่อผู้ดูแลระบบ")
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(request.Password), []byte(user.Password)); err != nil {
		if errors.Is(err, errors.New("crypto/bcrypt: hashedPassword is not the hash of the given password")) {
			return User{}, Token{}, errors.New("รหัสผ่านไม่ถูกต้อง")
		} else {
			return User{}, Token{}, errors.New("ระบบขัดข้อง กรุณาติดต่อผู้ดูแลระบบ")
		}
	}

	token := Token{}
	token.AccessToken, err = GetAcessToken(user)
	if err != nil {
		return User{}, Token{}, errors.New("ระบบขัดข้อง กรุณาติดต่อผู้ดูแลระบบ")
	}

	token.RefreshToken, err = GetAcessToken(user)
	if err != nil {
		return User{}, Token{}, errors.New("ระบบขัดข้อง กรุณาติดต่อผู้ดูแลระบบ")
	}

	return user, token, nil
}

func GetUserByUserName(request LoginRequest) (User, error) {
	user := User{}
	err := request.Con.Where("username = ?", request.Username).First(&user).Error
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func GetAcessToken(user User) (string, error) {
	claims := jwt.MapClaims{}
	expTime, err := strconv.Atoi(os.Getenv("ACCESS_TOKEN_EXP_TIME"))
	if err != nil {
		return "", errors.New("ระบบขัดข้อง กรุณาติดต่อผู้ดูแลระบบ")
	}
	claims["exp"] = time.Now().Add(time.Duration(expTime) * time.Hour).Unix()

	claims["user_id"] = user.ID
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString([]byte(os.Getenv("SECRET_KEY")))
	if err != nil {
		return "", errors.New("ระบบขัดข้อง กรุณาติดต่อผู้ดูแลระบบ")
	}
	return accessToken, nil
}

func GetRefreshToken(user User) (string, error) {
	claims := jwt.MapClaims{}
	expTime, err := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXP_TIME"))
	if err != nil {
		return "", errors.New("ระบบขัดข้อง กรุณาติดต่อผู้ดูแลระบบ")
	}
	claims["exp"] = time.Now().Add(time.Duration(expTime) * time.Hour).Unix()

	claims["user_id"] = user.ID
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString([]byte(os.Getenv("SECRET_KEY")))
	if err != nil {
		return "", errors.New("ระบบขัดข้อง กรุณาติดต่อผู้ดูแลระบบ")
	}
	return accessToken, nil
}

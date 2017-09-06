package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/astaxie/beego"
	"github.com/dgrijalva/jwt-go"
)

// 创建自己的Claims
type JwtClaims struct {
	*jwt.StandardClaims
	//用户编号
	Uid int64
	//用户名
	Username string
	//权限id
	Idebtity int64
}

var (
	//盐
	secret []byte = []byte(beego.AppConfig.String("jwt::secret"))
	issuer        = beego.AppConfig.String("jwt::issuer")
)

// CreateJwtToken 生成一个jwttoken
func CreateJwtToken(id, identity int64, username string) (signedToken string, err error) {
	expireToken := time.Now().Add(time.Hour * 24).Unix()
	claims := JwtClaims{
		&jwt.StandardClaims{
			NotBefore: time.Now().Unix(),
			ExpiresAt: expireToken,
			Issuer:    issuer,
		},
		id,
		username,
		identity,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err = token.SignedString(secret)
	return

}

// DestoryJwtToken 删除JwtToken
func DestoryJwtToken() (signedToken string, err error) {
	claims := JwtClaims{
		&jwt.StandardClaims{
			NotBefore: int64(time.Now().Unix() - 99998),
			ExpiresAt: int64(time.Now().Unix() - 99999),
			Issuer:    "lives",
		},
		-1,
		"",
		-1,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err = token.SignedString(secret)
	return
}

// VerifyToken 得到一个JwtToken,然后验证是否合法,防止伪造
func VerifyJwtToken(jwtToken string) bool {
	_, err := jwt.Parse(jwtToken, func(*jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		fmt.Println("解析jwtToken失败.", err)
		return false
	}
	return true
}

// ParseJwtToken 解析token得到是自己创建的Claims
func ParseJwtToken(jwtToken string) (*JwtClaims, error) {
	var jwtclaim = &JwtClaims{}
	_, err := jwt.ParseWithClaims(jwtToken, jwtclaim, func(*jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		fmt.Println("解析jwtToken失败.", err)
		return nil, errors.New("解析jwtToken失败")
	}
	return jwtclaim, nil
}

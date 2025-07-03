package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
)

var db *sql.DB
var jwtKey = []byte("kunci-rahasia-token")

type Claims struct {
	AdminID int `json:"admin_id"`
	jwt.RegisteredClaims
}

func main() {
	var err error
	db, err = sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/gedung_db")
	if err != nil {
		log.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("✅ Koneksi ke database berhasil!")

	r := gin.Default()
	r.LoadHTMLGlob("templates/*.html")
	r.Static("/static", "./static")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "form.html", nil)
	})

	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", nil)
	})

	r.GET("/admin", func(c *gin.Context) {
		c.HTML(http.StatusOK, "admin.html", nil)
	})

	r.POST("/admin/login", func(c *gin.Context) {
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var adminID int
		err := db.QueryRow("SELECT id FROM admin WHERE username=? AND password=?", input.Username, input.Password).Scan(&adminID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Login gagal"})
			return
		}

		expTime := time.Now().Add(24 * time.Hour)
		claims := &Claims{
			AdminID: adminID,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expTime),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenStr, err := token.SignedString(jwtKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Gagal membuat token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Login berhasil",
			"token":   tokenStr,
		})
	})

	r.POST("/peminjaman", func(c *gin.Context) {
		var input struct {
			Nama     string `json:"nama"`
			Instansi string `json:"instansi"`
			Tanggal  string `json:"tanggal"`
			Kegiatan string `json:"kegiatan"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		_, err := db.Exec("INSERT INTO peminjaman (nama, instansi, tanggal, kegiatan, status) VALUES (?, ?, ?, ?, ?)",
			input.Nama, input.Instansi, input.Tanggal, input.Kegiatan, "Menunggu")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Gagal menyimpan data"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Pengajuan berhasil dikirim"})
	})

	r.GET("/peminjaman", AuthMiddleware, func(c *gin.Context) {
		rows, err := db.Query("SELECT id, nama, instansi, tanggal, kegiatan, status FROM peminjaman")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Gagal mengambil data"})
			return
		}
		defer rows.Close()

		var data []map[string]interface{}
		for rows.Next() {
			var (
				id       int
				nama     string
				instansi string
				tanggal  string
				kegiatan string
				status   string
			)
			if err := rows.Scan(&id, &nama, &instansi, &tanggal, &kegiatan, &status); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Gagal membaca data"})
				return
			}
			data = append(data, gin.H{
				"id":       id,
				"nama":     nama,
				"instansi": instansi,
				"tanggal":  tanggal,
				"kegiatan": kegiatan,
				"status":   status,
			})
		}
		c.JSON(http.StatusOK, data)
	})

	r.PUT("/peminjaman/:id", AuthMiddleware, func(c *gin.Context) {
		id := c.Param("id")
		var input struct {
			Status string `json:"status"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		_, err := db.Exec("UPDATE peminjaman SET status=? WHERE id=?", input.Status, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Gagal memperbarui status"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Status diperbarui"})
	})

	r.DELETE("/peminjaman/:id", AuthMiddleware, func(c *gin.Context) {
		id := c.Param("id")
		_, err := db.Exec("DELETE FROM peminjaman WHERE id=?", id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Gagal menghapus data"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Data berhasil dihapus"})
	})

	// ✅ Gunakan port dari environment (untuk Railway)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}

// Middleware JWT
func AuthMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Token tidak ditemukan"})
		c.Abort()
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Token tidak valid"})
		c.Abort()
		return
	}

	c.Set("admin_id", claims.AdminID)
	c.Next()
}

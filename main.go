package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique"`
	Password string // เก็บเป็น Hash
	Role     string // "member" หรือ "admin"
}

// Facility: เก็บข้อมูลเครื่องเล่น/โซน
type Facility struct {
	ID     uint `gorm:"primaryKey"`
	Name   string
	Status string // "available" หรือ "maintenance"
}

type Reservation struct {
	ID         uint `gorm:"primaryKey"`
	UserID     uint // ระบุความเป็นเจ้าของ
	FacilityID uint
	BookDate   string
	StartTime  string
	Facility   Facility `gorm:"foreignKey:FacilityID"` // สำหรับดึงข้อมูลมาแสดงผล
	User       User     `gorm:"foreignKey:UserID"`
}

type IssueReport struct {
	ID          uint `gorm:"primaryKey"`
	UserID      uint
	FacilityID  uint
	Description string
	Status      string   // "pending" หรือ "resolved"
	Facility    Facility `gorm:"foreignKey:FacilityID"`
	User        User     `gorm:"foreignKey:UserID"`
}

var db *gorm.DB
var tmpl *template.Template
var sessionSecret []byte

func main() {
	secret := os.Getenv("SESSION_SECRET")
	if secret == "" {
		if os.Getenv("RENDER_SERVICE_ID") != "" {
			log.Fatal("SESSION_SECRET must be configured on Render")
		}
		randomSecret := make([]byte, 32)
		if _, err := rand.Read(randomSecret); err != nil {
			log.Fatal("failed to initialize session secret: ", err)
		}
		secret = base64.RawURLEncoding.EncodeToString(randomSecret)
	}
	sessionSecret = []byte(secret)

	var err error
	databasePath := os.Getenv("DATABASE_PATH")
	if databasePath == "" {
		databasePath = "gym.db"
	}
	if databaseDir := filepath.Dir(databasePath); databaseDir != "." {
		if err := os.MkdirAll(databaseDir, 0755); err != nil {
			log.Fatal("failed to create database directory: ", err)
		}
	}
	db, err = gorm.Open(sqlite.Open(databasePath), &gorm.Config{})
	if err != nil {
		log.Fatal("failed to connect database: ", err)
	}

	db.AutoMigrate(&User{}, &Facility{}, &Reservation{}, &IssueReport{})
	adminPassword := os.Getenv("ADMIN_PASSWORD")
	if adminPassword == "" {
		if os.Getenv("RENDER_SERVICE_ID") != "" {
			log.Fatal("ADMIN_PASSWORD must be configured on Render")
		}
		adminPassword = "admin123"
	}
	seedData(adminPassword)

	// Parse HTML Templates (อยู่ด้านล่างสุดของไฟล์)
	tmpl = template.Must(template.New("").Parse(htmlTemplates))

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/register-page", registerPageHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/dashboard", dashboardHandler)         // หน้าหลักของ Member
	http.HandleFunc("/reserve", reserveHandler)             // 처리 Form 1: จอง
	http.HandleFunc("/cancel-reserve", cancelHandler)       // 처리 CRUD: ลบ (เฉพาะของตัวเอง)
	http.HandleFunc("/report-issue", reportHandler)         // 처리 Form 2: แจ้งซ่อม
	http.HandleFunc("/admin", adminHandler)                 // ฟีเจอร์ 5: หน้า Admin
	http.HandleFunc("/admin/facility", adminFacilityUpdate) // Admin อัปเดตสถานะเครื่อง
	http.HandleFunc("/admin/delete-user", adminDeleteUser)
	http.HandleFunc("/admin/delete-reservation", adminDeleteReservation)
	http.HandleFunc("/admin/delete-report", adminDeleteReport)

	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	fmt.Printf("Server is running on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// ==========================================
// 4. BUSINESS LOGIC & HANDLERS
// ==========================================

func indexHandler(w http.ResponseWriter, r *http.Request) {
	tmpl.ExecuteTemplate(w, "index", map[string]string{
		"Error": r.URL.Query().Get("error"),
	})
}

func registerPageHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]string{
		"Error": r.URL.Query().Get("error"),
	}
	tmpl.ExecuteTemplate(w, "registerPage", data)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		http.Redirect(w, r, "/register-page", http.StatusSeeOther)
		return
	}
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		username = strings.TrimSpace(username)
		password = strings.TrimSpace(password)

		if username == "" || password == "" {
			http.Redirect(w, r, "/register-page?error=empty", http.StatusSeeOther)
			return
		}

		var existing User
		if err := db.Where("username = ?", username).First(&existing).Error; err == nil {
			http.Redirect(w, r, "/register-page?error=duplicate", http.StatusSeeOther)
			return
		}

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		user := User{Username: username, Password: string(hashedPassword), Role: "member"}
		db.Create(&user)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	var user User
	result := db.Where("username = ?", username).First(&user)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		http.Redirect(w, r, "/?error=user-not-found", http.StatusSeeOther)
		return
	}
	if result.Error != nil {
		http.Error(w, "เกิดข้อผิดพลาด กรุณาลองใหม่ภายหลัง", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		http.Redirect(w, r, "/?error=wrong-password", http.StatusSeeOther)
		return
	}

	http.SetCookie(w, sessionCookie(r, user.ID, user.Role))
	if user.Role == "admin" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "user_id", Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "role", Value: "", Path: "/", MaxAge: -1})
	cookie := sessionCookie(r, 0, "")
	cookie.Value = ""
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// dashboardHandler: หน้าแสดงผลของ User และรับฟอร์ม (ฟีเจอร์ 4)
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	var user User
	db.First(&user, userID)

	var facilities []Facility
	db.Find(&facilities)

	var reservations []Reservation
	// ฟีเจอร์ 3: CRUD มีเจ้าของ - ดึงมาแสดงเฉพาะการจองของตัวเองเท่านั้น (Read)
	db.Preload("Facility").Where("user_id = ?", userID).Find(&reservations)

	var issueReports []IssueReport
	db.Preload("Facility").Where("user_id = ?", userID).Find(&issueReports)

	data := map[string]interface{}{
		"User":         user,
		"Facilities":   facilities,
		"Reservations": reservations,
		"IssueReports": issueReports,
	}
	tmpl.ExecuteTemplate(w, "dashboard", data)
}

// reserveHandler: รับข้อมูลจากฟอร์มที่ 1
func reserveHandler(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if r.Method == "POST" && userID != 0 {
		facID, _ := strconv.Atoi(r.FormValue("facility_id"))

		// ตรวจสอบคิวซ้ำ (Time Conflict)
		var count int64
		db.Model(&Reservation{}).Where("facility_id = ? AND book_date = ? AND start_time = ?",
			facID, r.FormValue("book_date"), r.FormValue("start_time")).Count(&count)

		if count == 0 {
			// สร้างข้อมูลใหม่ (Create)
			res := Reservation{
				UserID:     userID,
				FacilityID: uint(facID),
				BookDate:   r.FormValue("book_date"),
				StartTime:  r.FormValue("start_time"),
			}
			db.Create(&res)
		}
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// cancelHandler: ลบการจอง (ฟีเจอร์ 3: ลบได้เฉพาะของตัวเอง)
func cancelHandler(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	resID := r.URL.Query().Get("id")
	if userID != 0 && resID != "" {
		if _, err := strconv.Atoi(resID); err == nil {
			// บังคับให้ลบได้เฉพาะ reservation ที่เป็นของผู้ใช้ตัวเองเท่านั้น
			db.Where("id = ? AND user_id = ?", resID, userID).Delete(&Reservation{})
		}
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// reportHandler: รับข้อมูลจากฟอร์มที่ 2 (แจ้งปัญหา)
func reportHandler(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if r.Method == "POST" && userID != 0 {
		facID, _ := strconv.Atoi(r.FormValue("facility_id"))
		report := IssueReport{
			UserID:      userID,
			FacilityID:  uint(facID),
			Description: r.FormValue("description"),
			Status:      "pending",
		}
		db.Create(&report)
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// adminHandler: ฟีเจอร์ 5 - หน้าผู้ดูแลระบบอย่างน้อย 1 หน้า
func adminHandler(w http.ResponseWriter, r *http.Request) {
	role := getRole(r)
	if role != "admin" { // ตรวจสอบสิทธิ์ (ฟีเจอร์ 2)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	var facilities []Facility
	db.Find(&facilities)

	var reports []IssueReport
	db.Preload("Facility").Preload("User").Find(&reports)

	var allReservations []Reservation
	db.Preload("Facility").Preload("User").Find(&allReservations)

	var users []User
	db.Order("username").Find(&users)

	data := map[string]interface{}{
		"Facilities":   facilities,
		"Reports":      reports,
		"Reservations": allReservations,
		"Users":        users,
	}
	tmpl.ExecuteTemplate(w, "admin", data)
}

// adminFacilityUpdate: แอดมินจัดการสถานะอุปกรณ์
func adminFacilityUpdate(w http.ResponseWriter, r *http.Request) {
	if getRole(r) == "admin" && r.Method == "POST" {
		facID := r.FormValue("facility_id")
		status := r.FormValue("status")
		db.Model(&Facility{}).Where("id = ?", facID).Update("status", status)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	if getRole(r) != "admin" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	userID := r.URL.Query().Get("id")
	if userID != "" {
		db.Where("id = ?", userID).Delete(&User{})
		db.Where("user_id = ?", userID).Delete(&Reservation{})
		db.Where("user_id = ?", userID).Delete(&IssueReport{})
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func adminDeleteReservation(w http.ResponseWriter, r *http.Request) {
	if getRole(r) != "admin" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	resID := r.URL.Query().Get("id")
	if resID != "" {
		db.Where("id = ?", resID).Delete(&Reservation{})
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func adminDeleteReport(w http.ResponseWriter, r *http.Request) {
	if getRole(r) != "admin" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	reportID := r.URL.Query().Get("id")
	if reportID != "" {
		db.Where("id = ?", reportID).Delete(&IssueReport{})
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// ==========================================
// 5. HELPER FUNCTIONS
// ==========================================
func getUserID(r *http.Request) uint {
	userID, _ := readSession(r)
	return userID
}
func getRole(r *http.Request) string {
	_, role := readSession(r)
	return role
}
func sessionCookie(r *http.Request, userID uint, role string) *http.Cookie {
	payload := strconv.FormatUint(uint64(userID), 10) + ":" + role
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(encodedPayload))
	value := encodedPayload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return &http.Cookie{
		Name:     "gym_session",
		Value:    value,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
	}
}

func readSession(r *http.Request) (uint, string) {
	cookie, err := r.Cookie("gym_session")
	if err != nil {
		return 0, ""
	}
	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 {
		return 0, ""
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, ""
	}
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(parts[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return 0, ""
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, ""
	}
	fields := strings.SplitN(string(payload), ":", 2)
	if len(fields) != 2 || (fields[1] != "admin" && fields[1] != "member") {
		return 0, ""
	}
	userID, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil || userID == 0 {
		return 0, ""
	}
	return uint(userID), fields[1]
}
func seedData(adminPassword string) {
	// จำลองข้อมูลแอดมิน 1 คน และเครื่องเล่นเริ่มต้น
	var count int64
	db.Model(&User{}).Count(&count)
	if count == 0 {
		hash, _ := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
		db.Create(&User{Username: "admin", Password: string(hash), Role: "admin"})

		db.Create(&Facility{Name: "Treadmill 01 (ลู่วิ่ง)", Status: "available"})
		db.Create(&Facility{Name: "Treadmill 02 (ลู่วิ่ง)", Status: "available"})
		db.Create(&Facility{Name: "Squat Rack (โซนเวท)", Status: "available"})
		db.Create(&Facility{Name: "Pool Lane A (สระว่ายน้ำ)", Status: "available"})
	}
}

// ==========================================
// 6. EMBEDDED HTML TEMPLATES (ใช้ Tailwind CSS)
// ==========================================
const htmlTemplates = `
{{define "header"}}
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <title>Late-Night Gym Booker</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 p-8">
{{end}}

{{define "footer"}}
</body></html>
{{end}}

{{define "index"}}
	{{template "header"}}
	<div class="max-w-md mx-auto bg-white rounded-lg shadow-md p-6">
		<h2 class="text-2xl font-bold mb-4 text-center">เข้าสู่ระบบ (Login)</h2>
		{{if eq .Error "user-not-found"}}
			<div class="mb-4 rounded border border-red-300 bg-red-50 text-red-700 p-3 text-sm">ผู้ใช้นี้ยังไม่ลงทะเบียน</div>
		{{else if eq .Error "wrong-password"}}
			<div class="mb-4 rounded border border-red-300 bg-red-50 text-red-700 p-3 text-sm">รหัสผ่านไม่ถูกต้อง</div>
		{{end}}
		<form action="/login" method="POST" class="mb-4">
			<input type="text" name="username" placeholder="Username" class="w-full p-2 border rounded mb-2" required>
			<input type="password" name="password" placeholder="Password" class="w-full p-2 border rounded mb-4" required>
			<button type="submit" class="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600">Login</button>
		</form>
		<div class="mt-4 text-center">
			<a href="/register-page" class="text-blue-600 hover:underline font-semibold">ลงทะเบียนผู้ใช้งานใหม่</a>
		</div>
	</div>
	{{template "footer"}}
{{end}}

{{define "registerPage"}}
	{{template "header"}}
	<div class="max-w-md mx-auto bg-white rounded-lg shadow-md p-6">
		<h2 class="text-2xl font-bold mb-4 text-center">ลงทะเบียนผู้ใช้งานใหม่</h2>
		{{if eq .Error "duplicate"}}
			<div class="mb-4 rounded border border-red-300 bg-red-50 text-red-700 p-3 text-sm">
				Username นี้เคยลงทะเบียนแล้ว กรุณาสร้าง Username ใหม่
			</div>
		{{else if eq .Error "empty"}}
			<div class="mb-4 rounded border border-red-300 bg-red-50 text-red-700 p-3 text-sm">
				กรุณากรอก Username และ Password ให้ครบถ้วน
			</div>
		{{end}}
		<form action="/register" method="POST">
			<input type="text" name="username" placeholder="Username" class="w-full p-2 border rounded mb-2" required>
			<input type="password" name="password" placeholder="Password" class="w-full p-2 border rounded mb-4" required>
			<button type="submit" class="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600">Register</button>
		</form>
		<div class="mt-4 text-center">
			<a href="/" class="text-blue-600 hover:underline">กลับไปหน้าเข้าสู่ระบบ</a>
		</div>
	</div>
	{{template "footer"}}
{{end}}

{{define "dashboard"}}
	{{template "header"}}
	<div class="max-w-4xl mx-auto">
		<div class="flex justify-between items-center bg-white p-4 rounded shadow mb-6">
			<h1 class="text-xl font-bold">Welcome, {{.User.Username}} (Role: {{.User.Role}})</h1>
			<a href="/logout" class="bg-red-500 text-white px-4 py-2 rounded">Logout</a>
		</div>

		<div class="grid grid-cols-2 gap-6">
			<!-- ฟอร์มที่ 1: จองคิว -->
			<div class="bg-white p-6 rounded shadow">
				<h2 class="text-xl font-bold mb-4">🏋️ จองโซน/อุปกรณ์ (Form 1)</h2>
				<form action="/reserve" method="POST">
					<label class="block mb-2">เลือกอุปกรณ์:</label>
					<select name="facility_id" class="w-full p-2 border rounded mb-4" required>
						{{range .Facilities}}
							<option value="{{.ID}}" {{if eq .Status "maintenance"}}disabled{{end}}>
								{{.Name}} {{if eq .Status "maintenance"}}[ซ่อมบำรุง]{{end}}
							</option>
						{{end}}
					</select>
					<label class="block mb-2">วันที่:</label>
					<input type="date" name="book_date" class="w-full p-2 border rounded mb-4" required>
					<label class="block mb-2">เวลาเริ่ม:</label>
					<input type="time" name="start_time" class="w-full p-2 border rounded mb-4" required>
					<button type="submit" class="w-full bg-blue-500 text-white p-2 rounded">ยืนยันการจอง</button>
				</form>
			</div>

			<!-- ฟอร์มที่ 2: แจ้งปัญหา -->
			<div class="bg-white p-6 rounded shadow">
				<h2 class="text-xl font-bold mb-4">⚠️ แจ้งอุปกรณ์ชำรุด (Form 2)</h2>
				<form action="/report-issue" method="POST">
					<label class="block mb-2">อุปกรณ์ที่มีปัญหา:</label>
					<select name="facility_id" class="w-full p-2 border rounded mb-4" required>
						{{range .Facilities}}
							<option value="{{.ID}}">{{.Name}}</option>
						{{end}}
					</select>
					<label class="block mb-2">อาการชำรุด:</label>
					<textarea name="description" class="w-full p-2 border rounded mb-4" required></textarea>
					<button type="submit" class="w-full bg-yellow-500 text-white p-2 rounded">ส่งรายงานแจ้งซ่อม</button>
				</form>
			</div>
		</div>

		<!-- แสดงข้อมูล CRUD ของผู้ใช้ -->
		<div class="bg-white p-6 rounded shadow mt-6">
			<h2 class="text-xl font-bold mb-4">📅 ประวัติการจองของฉัน (ลบได้เฉพาะของตัวเอง)</h2>
			<table class="w-full text-left border-collapse">
				<thead>
					<tr class="border-b"><th class="py-2">อุปกรณ์</th><th>วันที่</th><th>เวลา</th><th>จัดการ</th></tr>
				</thead>
				<tbody>
					{{range .Reservations}}
					<tr class="border-b">
						<td class="py-2">{{.Facility.Name}}</td>
						<td>{{.BookDate}}</td>
						<td>{{.StartTime}}</td>
						<td>
							<a href="/cancel-reserve?id={{.ID}}" class="text-red-500 hover:underline">ยกเลิกคิว (Delete)</a>
						</td>
					</tr>
					{{else}}
					<tr><td colspan="4" class="py-4 text-center text-gray-500">ยังไม่มีประวัติการจอง</td></tr>
					{{end}}
				</tbody>
			</table>
		</div>

		<div class="bg-white p-6 rounded shadow mt-6">
			<h2 class="text-xl font-bold mb-4">🛠️ รายการแจ้งซ่อมของฉัน</h2>
			<table class="w-full text-left border-collapse">
				<thead>
					<tr class="border-b"><th class="py-2">อุปกรณ์</th><th>รายละเอียด</th><th>สถานะ</th></tr>
				</thead>
				<tbody>
					{{range .IssueReports}}
					<tr class="border-b">
						<td class="py-2">{{.Facility.Name}}</td>
						<td>{{.Description}}</td>
						<td>{{.Status}}</td>
					</tr>
					{{else}}
					<tr><td colspan="3" class="py-4 text-center text-gray-500">ยังไม่มีการแจ้งซ่อม</td></tr>
					{{end}}
				</tbody>
			</table>
		</div>
	</div>
	{{template "footer"}}
{{end}}

{{define "admin"}}
	{{template "header"}}
	<div class="max-w-6xl mx-auto">
		<div class="flex justify-between items-center bg-gray-800 text-white p-4 rounded shadow mb-6">
			<h1 class="text-xl font-bold">🛠️ Admin Dashboard</h1>
			<a href="/logout" class="bg-red-500 text-white px-4 py-2 rounded">Logout</a>
		</div>

		<div class="grid grid-cols-2 gap-6">
			<!-- จัดการสถานะเครื่องเล่น -->
			<div class="bg-white p-6 rounded shadow">
				<h2 class="text-xl font-bold mb-4">จัดการสถานะอุปกรณ์</h2>
				<ul>
					{{range .Facilities}}
					<li class="flex justify-between items-center border-b py-2">
						<span>{{.Name}} - <strong>{{.Status}}</strong></span>
						<form action="/admin/facility" method="POST" class="inline">
							<input type="hidden" name="facility_id" value="{{.ID}}">
							<select name="status" class="border p-1 text-sm">
								<option value="available" {{if eq .Status "available"}}selected{{end}}>Available</option>
								<option value="maintenance" {{if eq .Status "maintenance"}}selected{{end}}>Maintenance</option>
							</select>
							<button type="submit" class="bg-blue-500 text-white px-2 py-1 rounded text-sm">อัปเดต</button>
						</form>
					</li>
					{{end}}
				</ul>
			</div>

			<!-- รายการแจ้งซ่อม -->
			<div class="bg-white p-6 rounded shadow">
				<h2 class="text-xl font-bold mb-4">รายการแจ้งซ่อมจาก User</h2>
				<ul>
					{{range .Reports}}
					<li class="border-b py-2 flex justify-between items-start gap-3">
						<div>
							<span class="text-red-500 font-bold">[{{.Facility.Name}}]</span> 
							แจ้งโดย {{.User.Username}} <br>
							<span class="text-gray-600">อาการ: {{.Description}}</span>
						</div>
						<a href="/admin/delete-report?id={{.ID}}" class="text-red-500 hover:underline text-sm font-semibold">ลบ</a>
					</li>
					{{else}}
					<li class="text-gray-500">ไม่มีการแจ้งซ่อม</li>
					{{end}}
				</ul>
			</div>
		</div>

		<div class="bg-white p-6 rounded shadow mt-6">
			<h2 class="text-xl font-bold mb-4">ประวัติการจองทั้งหมดของสมาชิก</h2>
			<table class="w-full text-left border-collapse">
				<thead>
					<tr class="border-b">
						<th class="py-2">ผู้ใช้</th>
						<th>อุปกรณ์</th>
						<th>วันที่</th>
						<th>เวลา</th>
						<th>จัดการ</th>
					</tr>
				</thead>
				<tbody>
					{{range .Reservations}}
					<tr class="border-b">
						<td class="py-2">{{.User.Username}}</td>
						<td>{{.Facility.Name}}</td>
						<td>{{.BookDate}}</td>
						<td>{{.StartTime}}</td>
						<td><a href="/admin/delete-reservation?id={{.ID}}" class="text-red-500 hover:underline">ลบ</a></td>
					</tr>
					{{else}}
					<tr><td colspan="5" class="py-4 text-center text-gray-500">ไม่มีการจอง</td></tr>
					{{end}}
				</tbody>
			</table>
		</div>

		<div class="bg-white p-6 rounded shadow mt-6">
			<h2 class="text-xl font-bold mb-4">รายชื่อผู้ใช้งานทั้งหมด</h2>
			<table class="w-full text-left border-collapse">
				<thead>
					<tr class="border-b">
						<th class="py-2">Username</th>
						<th>Role</th>
						<th>จัดการ</th>
					</tr>
				</thead>
				<tbody>
					{{range .Users}}
					<tr class="border-b">
						<td class="py-2">{{.Username}}</td>
						<td>{{.Role}}</td>
						<td>
							{{if ne .Role "admin"}}
							<a href="/admin/delete-user?id={{.ID}}" class="text-red-500 hover:underline">ลบผู้ใช้</a>
							{{else}}
							<span class="text-gray-400">-</span>
							{{end}}
						</td>
					</tr>
					{{else}}
					<tr><td colspan="3" class="py-4 text-center text-gray-500">ไม่มีผู้ใช้งาน</td></tr>
					{{end}}
				</tbody>
			</table>
		</div>
	</div>
	{{template "footer"}}
{{end}}
`

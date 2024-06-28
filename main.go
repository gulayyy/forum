package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
)

var (
	tmpl        *template.Template
	soruYetkisi = make(map[string]bool)
	store       = sessions.NewCookieStore([]byte("super-secret-key"))
)

type datahata struct {
	GirisError    string
	UsernameError string
	EmailError    string
	PasswordError string
	Sorugiris     string
}

type Question struct {
	ID          int
	Title       string
	Description string
	Username    string
	CreatedAt   time.Time
	Likes       int
	Dislikes    int
	Comments    []Comment
}

type Comment struct {
	ID           int
	UserID       int    // Yorumu yapan kullanıcının ID'si
	KullaniciAdi string // Kullanıcı adını kaldırabiliriz
	Comment      string
	CreatedAt    time.Time
	Clikes       int
	Cdislikes    int
}
type PageData struct {
	Comments []Comment
	Question struct {
		ID int
	}
}

func main() {
	if err := initializeDatabase(); err != nil {
		fmt.Println("Veritabanı başlatma hatası:", err)
		return
	}
	var err error
	tmpl, err = template.ParseFiles("template/index.html", "template/dene.html", "template/kayit.html", "template/questions.html", "template/comment.html", "template/kategori.html", "template/liked_questions.html", "template/userquestions.html", "template/QuestionComment.html")
	if err != nil {
		fmt.Println("Şablon oluşturma hatası:", err)
		return
	}

	http.HandleFunc("/", Anasayfa)
	http.HandleFunc("/register", Giris)
	http.HandleFunc("/kayit", Kayit)
	http.HandleFunc("/questions", QuestionsHandler)
	http.HandleFunc("/addquestion", AddQuestionHandler)
	http.HandleFunc("/logout", Cikis)
	http.HandleFunc("/comment", YorumYap)
	http.HandleFunc("/kategoriAl", KategoriyiAl)
	http.HandleFunc("/like", LikeHandler)
	http.HandleFunc("/dislike", DislikeHandler)
	http.HandleFunc("/likecomment", LikeCommentHandler)
	http.HandleFunc("/dislikecomment", DislikeCommentHandler)
	http.HandleFunc("/liked-questions", LikedQuestionsHandler)
	http.HandleFunc("/userquestions", UserQuestionsHandler)
	http.HandleFunc("/QuestionComment", UserCommentedQuestionsHandler)

	fmt.Println("Port dinleniyor...")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("Sunucu başlatılamadı:", err)
		return
	}
}

func Anasayfa(w http.ResponseWriter, r *http.Request) {
	if err := tmpl.ExecuteTemplate(w, "index.html", nil); err != nil {
		handleInternalServerError(w, err)
	}
}
func initializeDatabase() error {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		return fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
	}
	defer db.Close()

	query := `
	CREATE TABLE IF NOT EXISTS UserQuestionLikes (
		ID INTEGER PRIMARY KEY AUTOINCREMENT,
		UserID INTEGER,
		QuestionID INTEGER,
		Liked BOOLEAN,
		UNIQUE(UserID, QuestionID)
	);
	`
	_, err = db.Exec(query)
	if err != nil {
		return fmt.Errorf("tablolar oluşturulurken hata oluştu: %v", err)
	}

	return nil
}

func Giris(w http.ResponseWriter, r *http.Request) {
	hatalar := datahata{}
	hasError := false

	if r.Method == http.MethodPost {
		kullaniciad := r.FormValue("username")
		gsifre := r.FormValue("password")

		if sonuc1, err1 := KullaniciVarMi(kullaniciad); err1 != nil {
			handleInternalServerError(w, err1)
			return
		} else if !sonuc1 {
			hatalar.GirisError = "Kullanıcı mevcut değil."
			hasError = true
		} else {
			if sonuc, err := KullaniciDogru(kullaniciad, gsifre); err != nil {
				handleInternalServerError(w, err)
				return
			} else if !sonuc {
				hatalar.GirisError = "Şifre hatalı."
				hasError = true
			} else {
				// Store user ID in session
				session, _ := store.Get(r, "session-name")
				session.Values["username"] = kullaniciad
				session.Save(r, w)

				soruYetkisi[kullaniciad] = true
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
		}

		if hasError {
			if err := tmpl.ExecuteTemplate(w, "dene.html", hatalar); err != nil {
				handleInternalServerError(w, err)
			}
			return
		}
	} else {
		if err := tmpl.ExecuteTemplate(w, "dene.html", nil); err != nil {
			handleInternalServerError(w, err)
		}
	}
}

func Cikis(w http.ResponseWriter, r *http.Request) {
	// Oturumu sonlandır
	session, _ := store.Get(r, "session-name")
	username, ok := session.Values["username"].(string)
	if ok {
		// Kullanıcı yetkisini kaldır
		delete(soruYetkisi, username)
	}

	session.Options.MaxAge = -1 // Oturumu geçersiz kıl
	session.Save(r, w)          // Oturumu kaydet

	// Anasayfaya yönlendir
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func Kayit(w http.ResponseWriter, r *http.Request) {
	hatalar := datahata{}
	hasError := false

	if r.Method == http.MethodPost {
		ad := r.FormValue("name")
		kullaniciAdi := r.FormValue("ad")
		mail := r.FormValue("mail")
		sifre := r.FormValue("sifre")

		if strings.Contains(sifre, " ") {
			hatalar.PasswordError = "Şifre boşluk içermemeli."
			hasError = true
		}

		if len(sifre) < 8 {
			hatalar.PasswordError = "Şifre en az 8 karakterden oluşmalı."
			hasError = true
		}

		hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(sifre)
		hasLower := regexp.MustCompile(`[a-z]`).MatchString(sifre)
		hasDigit := regexp.MustCompile(`[0-9]`).MatchString(sifre)

		if !hasUpper {
			hatalar.PasswordError = "Şifre en az bir büyük harf içermeli."
			hasError = true
		}
		if !hasLower {
			hatalar.PasswordError = "Şifre en az bir küçük harf içermeli."
			hasError = true
		}
		if !hasDigit {
			hatalar.PasswordError = "Şifre en az bir rakam içermeli."
			hasError = true
		}

		if sonuc, err := MailKont(mail); err != nil {
			handleInternalServerError(w, err)
			return
		} else if sonuc {
			hatalar.EmailError = "Mail mevcut, lütfen değiştirin."
			hasError = true
		}

		if exists, err := KullaniciVarMi(kullaniciAdi); err != nil {
			handleInternalServerError(w, err)
			return
		} else if exists {
			hatalar.UsernameError = "Kullanıcı adı mevcut, lütfen değiştirin."
			hasError = true
		}

		if hasError {
			if err := tmpl.ExecuteTemplate(w, "kayit.html", hatalar); err != nil {
				handleInternalServerError(w, err)
			}
			return
		}

		// Parolayı hashleyerek kaydet
		hashedPassword, err := ParolaHashle(sifre)
		if err != nil {
			handleInternalServerError(w, err)
			return
		}

		if err := KullaniciEkle(ad, kullaniciAdi, mail, string(hashedPassword)); err != nil {
			handleInternalServerError(w, err)
			return
		}

		session, _ := store.Get(r, "session-name")
		session.Values["username"] = kullaniciAdi
		session.Save(r, w)
		soruYetkisi[kullaniciAdi] = true

		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		if err := tmpl.ExecuteTemplate(w, "kayit.html", nil); err != nil {
			handleInternalServerError(w, err)
		}
	}
}

// ParolaHashle parolayı bcrypt kullanarak hashler
func ParolaHashle(parola string) ([]byte, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(parola), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return hashedPassword, nil
}

// ParolaDogrula kullanıcı parolasını ve hashlenmiş parolayı karşılaştırır
func ParolaDogrula(parola string, hashedPassword []byte) error {
	return bcrypt.CompareHashAndPassword(hashedPassword, []byte(parola))
}

func QuestionsHandler(w http.ResponseWriter, r *http.Request) {
	questions, err := getQuestions()
	if err != nil {
		handleInternalServerError(w, err)
		return
	}

	data := struct {
		Questions []Question
		Sorugiris string
	}{
		Questions: questions,
		Sorugiris: "",
	}

	if err := tmpl.ExecuteTemplate(w, "questions.html", data); err != nil {
		handleInternalServerError(w, err)
	}
}

func getQuestions() ([]Question, error) {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		return nil, fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT ID, Title, Description, Username, CreatedAt, Likes, Dislikes FROM questions")
	if err != nil {
		return nil, fmt.Errorf("sorgu sırasında hata oluştu: %v", err)
	}
	defer rows.Close()

	var questions []Question
	for rows.Next() {
		var question Question
		if err := rows.Scan(&question.ID, &question.Title, &question.Description, &question.Username, &question.CreatedAt, &question.Likes, &question.Dislikes); err != nil {
			return nil, fmt.Errorf("satır tarama sırasında hata oluştu: %v", err)
		}

		// Her soru için yorumları al
		comments, err := GetCommentsForQuestion(question.ID)
		if err != nil {
			return nil, fmt.Errorf("yorumlar alınırken hata oluştu: %v", err)
		}
		question.Comments = comments

		questions = append(questions, question)
	}
	return questions, nil
}

func AddQuestion(title string, description []string, username string) error {
    db, err := sql.Open("sqlite3", "./Forum.db")
    if err != nil {
        return fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
    }
    defer db.Close()

    // Concatenate description slice into a single string
    descriptionStr := strings.Join(description, ", ")

    query := "INSERT INTO questions (Title, Description, Username, CreatedAt, Likes, Dislikes) VALUES (?, ?, ?, ?, 0, 0)"
    _, err = db.Exec(query, title, descriptionStr, username, time.Now())
    if err != nil {
        return fmt.Errorf("soru eklenirken hata oluştu: %v", err)
    }
    return nil
}


func AddQuestionHandler(w http.ResponseWriter, r *http.Request) {
	hatalar := datahata{}
	hasError := false

	session, _ := store.Get(r, "session-name")
	kullaniciad, ok := session.Values["username"].(string)
	if !ok || !soruYetkisi[kullaniciad] {
		hatalar.Sorugiris = "Soru sormak için giriş yapmalısınız."
		hasError = true
	}

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			handleInternalServerError(w, err)
			return
		}

		if hasError {
			questions, err := getQuestions()
			if err != nil {
				handleInternalServerError(w, err)
				return
			}

			data := struct {
				Questions []Question
				Sorugiris string
			}{
				Questions: questions,
				Sorugiris: hatalar.Sorugiris,
			}

			if err := tmpl.ExecuteTemplate(w, "questions.html", data); err != nil {
				handleInternalServerError(w, err)
			}
			return
		}

		title := r.FormValue("title")
		description := r.Form["kategori[]"]

		err = AddQuestion(title, description, kullaniciad)
		if err != nil {
			handleInternalServerError(w, err)
			return
		}

		http.Redirect(w, r, "/questions", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/questions", http.StatusSeeOther)
	}
}

func UserExists(KullaniciAdi string) bool {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		// Veritabanına bağlanamadık, kullanıcıyı kontrol edemeyiz
		return false
	}
	defer db.Close()

	var count int
	query := `SELECT COUNT(*) FROM Users WHERE KullaniciAdi = ?`
	err = db.QueryRow(query, KullaniciAdi).Scan(&count)
	if err != nil {
		// Sorgu başarısız oldu, kullanıcıyı kontrol edemeyiz
		return false
	}
	return count > 0
}

func handleInternalServerError(w http.ResponseWriter, err error) {
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	fmt.Println("İç sunucu hatası:", err)
}

func KullaniciDogru(kullaniciadi, gsifre string) (bool, error) {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		return false, fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
	}
	defer db.Close()

	var hashedPassword string
	query := `SELECT Sifre FROM Users WHERE KullaniciAdi = ?`
	err = db.QueryRow(query, kullaniciadi).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("sorgu sırasında hata oluştu: %v", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(gsifre))
	if err != nil {
		return false, nil
	}

	return true, nil
}

func KullaniciVarMi(kullaniciadi string) (bool, error) {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		return false, fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
	}
	defer db.Close()

	var count int
	query := `SELECT COUNT(*) FROM Users WHERE KullaniciAdi = ?`
	err = db.QueryRow(query, kullaniciadi).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("sorgu sırasında hata oluştu: %v", err)
	}

	return count > 0, nil
}

func KullaniciEkle(ad, kullaniciAdi, mail, sifre string) error {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		return fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
	}
	defer db.Close()

	query := `INSERT INTO Users (Ad, KullaniciAdi, Email, Sifre) VALUES (?, ?, ?, ?)`
	_, err = db.Exec(query, ad, kullaniciAdi, mail, sifre)
	if err != nil {
		return fmt.Errorf("kullanıcı eklenirken hata oluştu: %v", err)
	}

	return nil
}

func MailKont(mail string) (bool, error) {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		return false, fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
	}
	defer db.Close()

	var count int
	query := `SELECT COUNT(*) FROM Users WHERE Email = ?`
	err = db.QueryRow(query, mail).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("sorgu sırasında hata oluştu: %v", err)
	}

	return count > 0, nil
}

// Function to handle adding comments
func YorumYap(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	kullaniciadi, ok := session.Values["username"].(string)
	if !ok {
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		comment := r.FormValue("comment")
		questionIDStr := r.FormValue("question_id")
		questionID, err := strconv.Atoi(questionIDStr)
		if err != nil {
			fmt.Println("Geçersiz question_id:", questionIDStr, err)
			http.Error(w, "Geçersiz question_id", http.StatusBadRequest)
			return
		}

		if err := CommentEkle(kullaniciadi, comment, questionID); err != nil {
			handleInternalServerError(w, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/comment?question_id=%d", questionID), http.StatusSeeOther)
	} else {
		questionIDStr := r.URL.Query().Get("question_id")
		questionID, err := strconv.Atoi(questionIDStr)
		if err != nil {
			fmt.Println("Geçersiz question_id:", questionIDStr, err)
			http.Error(w, "Geçersiz question_id", http.StatusBadRequest)
			return
		}

		question, err := GetQuestionByID(questionID)
		if err != nil {
			handleInternalServerError(w, err)
			return
		}

		comments, err := GetCommentsForQuestion(questionID)
		if err != nil {
			handleInternalServerError(w, err)
			return
		}

		data := struct {
			Question Question
			Comments []Comment
		}{
			Question: question,
			Comments: comments,
		}

		if err := tmpl.ExecuteTemplate(w, "comment.html", data); err != nil {
			handleInternalServerError(w, err)
		}
	}
}

func CommentEkle(kullaniciadi, comment string, questionID int) error {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		return fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
	}
	defer db.Close()

	// Kullanıcı adından kullanıcı ID'sini al
	var userID int
	err = db.QueryRow("SELECT ID FROM Users WHERE KullaniciAdi = ?", kullaniciadi).Scan(&userID)
	if err != nil {
		return fmt.Errorf("kullanıcı ID'sini alırken hata oluştu: %v", err)
	}

	query := "INSERT INTO Comments (User_id, Comment, CreatedAt, Question_id) VALUES (?, ?, ?, ?)"
	_, err = db.Exec(query, userID, comment, time.Now(), questionID)
	if err != nil {
		return fmt.Errorf("yorum eklenirken hata oluştu: %v", err)
	}
	return nil
}
func GetQuestionByID(questionID int) (Question, error) {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		return Question{}, fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
	}
	defer db.Close()

	var question Question
	query := "SELECT ID, Title, Description, Username, CreatedAt, Likes, Dislikes FROM questions WHERE ID = ?"
	err = db.QueryRow(query, questionID).Scan(&question.ID, &question.Title, &question.Description, &question.Username, &question.CreatedAt, &question.Likes, &question.Dislikes)
	if err != nil {
		return Question{}, fmt.Errorf("soru getirilirken hata oluştu: %v", err)
	}

	// Her soru için yorumları al
	comments, err := GetCommentsForQuestion(question.ID)
	if err != nil {
		return Question{}, fmt.Errorf("yorumlar alınırken hata oluştu: %v", err)
	}
	question.Comments = comments

	return question, nil
}
func GetCommentsForQuestion(questionID int) ([]Comment, error) {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		return nil, fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
	}
	defer db.Close()

	query := `
		SELECT c.ID, u.KullaniciAdi, c.Comment, c.CreatedAt, c.Likes, c.Dislikes
		FROM Comments c
		JOIN Users u ON c.User_id = u.ID
		WHERE c.Question_id = ?
	`
	rows, err := db.Query(query, questionID)
	if err != nil {
		return nil, fmt.Errorf("sorgu sırasında hata oluştu: %v", err)
	}
	defer rows.Close()

	var comments []Comment
	for rows.Next() {
		var comment Comment
		if err := rows.Scan(&comment.ID, &comment.KullaniciAdi, &comment.Comment, &comment.CreatedAt, &comment.Clikes, &comment.Cdislikes); err != nil {
			return nil, fmt.Errorf("satır tarama sırasında hata oluştu: %v", err)
		}
		comments = append(comments, comment)
	}
	return comments, nil
}

func KategoriyiAl(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Form verisini al
		kategori := r.FormValue("al")

		// Kategori dizisi oluştur
		kategoriler := []string{kategori}

		// Kategoriye göre soruları al
		questions, err := KategoriyeGoreGetir(kategoriler)
		if err != nil {
			handleInternalServerError(w, err)
			return
		}

		// Template verisi oluştur
		data := struct {
			Category  []string
			Questions []Question
		}{
			Category:  kategoriler,
			Questions: questions,
		}

		// Template'i render et
		if err := tmpl.ExecuteTemplate(w, "kategori.html", data); err != nil {
			handleInternalServerError(w, err)
		}
	}
}

func KategoriyeGoreGetir(kategoriler []string) ([]Question, error) {
    db, err := sql.Open("sqlite3", "./Forum.db")
    if err != nil {
        return nil, fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
    }
    defer db.Close()

    var questions []Question
    var rows *sql.Rows

    // Temel sorguyu oluştur
    query := `SELECT ID, Title, Description, Username, CreatedAt, Likes, Dislikes FROM Questions`
    var args []interface{}  // interface herhangi bir veri türünü temsil edebilir farklı türlerde veri eklemmemize yardımcı olur.

    if len(kategoriler) > 0 {
        // Eğer kategoriler varsa WHERE koşulunu ekle
        query += " WHERE"
        for i, kategori := range kategoriler {
            if i > 0 {
                query += " OR" // kategoriler diliminde birden fazla değer varsa diye 
            }
            query += " Description LIKE ?"
            args = append(args, "%"+kategori+"%")   // istenen metni aramak için bu yöntemi kullnadık.
        }
    }

    rows, err = db.Query(query, args...)
    if err != nil {
        return nil, fmt.Errorf("sorgu sırasında hata oluştu: %v", err)
    }
    defer rows.Close()

    for rows.Next() {
        var question Question
        if err := rows.Scan(&question.ID, &question.Title, &question.Description, &question.Username, &question.CreatedAt, &question.Likes, &question.Dislikes); err != nil {
            return nil, fmt.Errorf("satır tarama sırasında hata oluştu: %v", err)
        }

        comments, err := GetCommentsForQuestion(question.ID)
        if err != nil {
            return nil, fmt.Errorf("yorumlar alınırken hata oluştu: %v", err)
        }
        question.Comments = comments

        questions = append(questions, question)
    }

    return questions, nil
}

func UpdateLikeDislike(userID, questionID int, action string) error {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		return fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
	}
	defer db.Close()

	var currentStatus bool     // mevcut durum
	var hasPreviousAction bool // eskiden işlemi var mı onu kontrol etmek için.
	err = db.QueryRow("SELECT Liked FROM UserQuestionLikes WHERE UserID = ? AND QuestionID = ?", userID, questionID).Scan(&currentStatus)
	if err == nil {
		hasPreviousAction = true
	} else if err == sql.ErrNoRows {
		hasPreviousAction = false
	} else {
		return fmt.Errorf("kullanıcı durumu kontrol edilirken hata oluştu: %v", err)
	}

	if action == "like" {
		if hasPreviousAction {
			if currentStatus {
				_, err = db.Exec("DELETE FROM UserQuestionLikes WHERE UserID = ? AND QuestionID = ?", userID, questionID)
				_, err = db.Exec("UPDATE Questions SET Likes = Likes - 1 WHERE ID = ?", questionID)
			} else {
				_, err = db.Exec("UPDATE UserQuestionLikes SET Liked = 1 WHERE UserID = ? AND QuestionID = ?", userID, questionID)
				_, err = db.Exec("UPDATE Questions SET Likes = Likes + 1, Dislikes = Dislikes - 1 WHERE ID = ?", questionID)
			}
		} else {
			_, err = db.Exec("INSERT INTO UserQuestionLikes (UserID, QuestionID, Liked) VALUES (?, ?, 1)", userID, questionID)
			_, err = db.Exec("UPDATE Questions SET Likes = Likes + 1 WHERE ID = ?", questionID)
		}
	} else if action == "dislike" {
		if hasPreviousAction {
			if !currentStatus {
				_, err = db.Exec("DELETE FROM UserQuestionLikes WHERE UserID = ? AND QuestionID = ?", userID, questionID)
				_, err = db.Exec("UPDATE Questions SET Dislikes = Dislikes - 1 WHERE ID = ?", questionID)
			} else {
				_, err = db.Exec("UPDATE UserQuestionLikes SET Liked = 0 WHERE UserID = ? AND QuestionID = ?", userID, questionID)
				_, err = db.Exec("UPDATE Questions SET Likes = Likes - 1, Dislikes = Dislikes + 1 WHERE ID = ?", questionID)
			}
		} else {
			_, err = db.Exec("INSERT INTO UserQuestionLikes (UserID, QuestionID, Liked) VALUES (?, ?, 0)", userID, questionID)
			_, err = db.Exec("UPDATE Questions SET Dislikes = Dislikes + 1 WHERE ID = ?", questionID)
		}
	}

	if err != nil {
		return fmt.Errorf("güncelleme sırasında hata oluştu: %v", err)
	}
	return nil
}

func LikeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		session, _ := store.Get(r, "session-name")
		username, ok := session.Values["username"].(string)
		if !ok {
			http.Redirect(w, r, "/register", http.StatusSeeOther)
			return
		}

		userID, err := getUserIDByUsername(username)
		if err != nil {
			handleInternalServerError(w, err)
			return
		}

		idStr := r.FormValue("question_id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			handleInternalServerError(w, fmt.Errorf("geçersiz soru ID'si: %v", err))
			return
		}
		err = UpdateLikeDislike(userID, id, "like")
		if err != nil {
			handleInternalServerError(w, err)
			return
		}
		http.Redirect(w, r, "/questions", http.StatusSeeOther)
	}
}

func DislikeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		session, _ := store.Get(r, "session-name")
		username, ok := session.Values["username"].(string)
		if !ok {
			http.Redirect(w, r, "/register", http.StatusSeeOther)
			return
		}

		userID, err := getUserIDByUsername(username)
		if err != nil {
			handleInternalServerError(w, err)
			return
		}

		idStr := r.FormValue("question_id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			handleInternalServerError(w, fmt.Errorf("geçersiz soru ID'si: %v", err))
			return
		}
		err = UpdateLikeDislike(userID, id, "dislike")
		if err != nil {
			handleInternalServerError(w, err)
			return
		}
		http.Redirect(w, r, "/questions", http.StatusSeeOther)
	}
}

func getUserIDByUsername(username string) (int, error) {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		return 0, fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
	}
	defer db.Close()

	var userID int
	err = db.QueryRow("SELECT ID FROM Users WHERE KullaniciAdi = ?", username).Scan(&userID)
	if err != nil {
		return 0, fmt.Errorf("kullanıcı ID'si alırken hata oluştu: %v", err)
	}
	return userID, nil
}

func UpdateLikeDislikeForComment(userID, commentID int, action string) error {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		return fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
	}
	defer db.Close()

	var currentStatus bool
	var hasPreviousAction bool

	err = db.QueryRow("SELECT Liked FROM UserCommentLikes WHERE UserID = ? AND CommentID = ?", userID, commentID).Scan(&currentStatus)
	if err == nil {
		hasPreviousAction = true
	} else if err == sql.ErrNoRows {
		hasPreviousAction = false
	} else {
		return fmt.Errorf("kullanıcı durumu kontrol edilirken hata oluştu: %v", err)
	}

	if action == "like" {
		if hasPreviousAction {
			if currentStatus {
				_, err = db.Exec("DELETE FROM UserCommentLikes WHERE UserID = ? AND CommentID = ?", userID, commentID)
				if err != nil {
					return fmt.Errorf("beğeni silinirken hata oluştu: %v", err)
				}
				_, err = db.Exec("UPDATE Comments SET Likes = Likes - 1 WHERE ID = ?", commentID)
			} else {
				_, err = db.Exec("UPDATE UserCommentLikes SET Liked = 1 WHERE UserID = ? AND CommentID = ?", userID, commentID)
				if err != nil {
					return fmt.Errorf("beğeni güncellenirken hata oluştu: %v", err)
				}
				_, err = db.Exec("UPDATE Comments SET Likes = Likes + 1, Dislikes = Dislikes - 1 WHERE ID = ?", commentID)
			}
		} else {
			_, err = db.Exec("INSERT INTO UserCommentLikes (UserID, CommentID, Liked) VALUES (?, ?, 1)", userID, commentID)
			if err != nil {
				return fmt.Errorf("beğeni eklenirken hata oluştu: %v", err)
			}
			_, err = db.Exec("UPDATE Comments SET Likes = Likes + 1 WHERE ID = ?", commentID)
		}
	} else if action == "dislike" {
		if hasPreviousAction {
			if !currentStatus {
				_, err = db.Exec("DELETE FROM UserCommentLikes WHERE UserID = ? AND CommentID = ?", userID, commentID)
				if err != nil {
					return fmt.Errorf("beğenmeme silinirken hata oluştu: %v", err)
				}
				_, err = db.Exec("UPDATE Comments SET Dislikes = Dislikes - 1 WHERE ID = ?", commentID)
			} else {
				_, err = db.Exec("UPDATE UserCommentLikes SET Liked = 0 WHERE UserID = ? AND CommentID = ?", userID, commentID)
				if err != nil {
					return fmt.Errorf("beğenmeme güncellenirken hata oluştu: %v", err)
				}
				_, err = db.Exec("UPDATE Comments SET Likes = Likes - 1, Dislikes = Dislikes + 1 WHERE ID = ?", commentID)
			}
		} else {
			_, err = db.Exec("INSERT INTO UserCommentLikes (UserID, CommentID, Liked) VALUES (?, ?, 0)", userID, commentID)
			if err != nil {
				return fmt.Errorf("beğenmeme eklenirken hata oluştu: %v", err)
			}
			_, err = db.Exec("UPDATE Comments SET Dislikes = Dislikes + 1 WHERE ID = ?", commentID)
		}
	}

	if err != nil {
		return fmt.Errorf("güncelleme sırasında hata oluştu: %v", err)
	}
	return nil
}

func LikeCommentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		session, _ := store.Get(r, "session-name")
		username, ok := session.Values["username"].(string)
		if !ok {
			http.Redirect(w, r, "/register", http.StatusSeeOther)
			return
		}

		userID, err := getUserIDByUsername(username)
		if err != nil {
			handleInternalServerError(w, err)
			return
		}

		idStr := r.FormValue("comment_id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			handleInternalServerError(w, fmt.Errorf("geçersiz yorum ID'si: %v", err))
			return
		}
		err = UpdateLikeDislikeForComment(userID, id, "like")
		if err != nil {
			handleInternalServerError(w, err)
			return
		}
		http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
	}
}

func DislikeCommentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		session, _ := store.Get(r, "session-name")
		username, ok := session.Values["username"].(string)
		if !ok {
			http.Redirect(w, r, "/register", http.StatusSeeOther)
			return
		}

		userID, err := getUserIDByUsername(username)
		if err != nil {
			handleInternalServerError(w, err)
			return
		}

		idStr := r.FormValue("comment_id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			handleInternalServerError(w, fmt.Errorf("geçersiz yorum ID'si: %v", err))
			return
		}
		err = UpdateLikeDislikeForComment(userID, id, "dislike")
		if err != nil {
			handleInternalServerError(w, err)
			return
		}
		http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
	}
}
func LikedQuestionsHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	username, ok := session.Values["username"].(string)
	if !ok {
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}

	// Kullanıcının beğendiği soruları al
	likedQuestions, err := getLikedQuestions(username)
	if err != nil {
		handleInternalServerError(w, err)
		return
	}

	// Beğenilen soruları HTML şablonuna gönder
	data := struct {
		Questions []Question
		Username  string
	}{
		Questions: likedQuestions,
		Username:  username,
	}
	if err := tmpl.ExecuteTemplate(w, "liked_questions.html", data); err != nil {
		handleInternalServerError(w, err)
	}
}

func getLikedQuestions(username string) ([]Question, error) {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		return nil, fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
	}
	defer db.Close()

	query := `
        SELECT q.ID, q.Title, q.Description, q.Username, q.CreatedAt, q.Likes, q.Dislikes
        FROM questions q
        JOIN UserQuestionLikes uql ON q.ID = uql.QuestionID
        JOIN Users u ON u.ID = uql.UserID
        WHERE u.KullaniciAdi = ?
    `
	rows, err := db.Query(query, username)
	if err != nil {
		return nil, fmt.Errorf("sorgu sırasında hata oluştu: %v", err)
	}
	defer rows.Close()

	var likedQuestions []Question
	for rows.Next() {
		var question Question
		if err := rows.Scan(&question.ID, &question.Title, &question.Description, &question.Username, &question.CreatedAt, &question.Likes, &question.Dislikes); err != nil {
			return nil, fmt.Errorf("satır tarama sırasında hata oluştu: %v", err)
		}

		// Her soru için yorumları al
		comments, err := GetCommentsForQuestion(question.ID)
		if err != nil {
			return nil, fmt.Errorf("yorumlar alınırken hata oluştu: %v", err)
		}
		question.Comments = comments

		likedQuestions = append(likedQuestions, question)
	}
	return likedQuestions, nil
}

func GetQuestionsByUser(username string) ([]Question, error) {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		return nil, fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
	}
	defer db.Close()

	query := `SELECT ID, Title, Description, Username, CreatedAt, Likes, Dislikes FROM Questions WHERE Username = ?`
	rows, err := db.Query(query, username)
	if err != nil {
		return nil, fmt.Errorf("sorgu sırasında hata oluştu: %v", err)
	}
	defer rows.Close()

	var questions []Question
	for rows.Next() {
		var question Question
		if err := rows.Scan(&question.ID, &question.Title, &question.Description, &question.Username, &question.CreatedAt, &question.Likes, &question.Dislikes); err != nil {
			return nil, fmt.Errorf("satır tarama sırasında hata oluştu: %v", err)
		}

		// Her soru için yorumları al
		comments, err := GetCommentsForQuestion(question.ID)
		if err != nil {
			return nil, fmt.Errorf("yorumlar alınırken hata oluştu: %v", err)
		}
		question.Comments = comments

		questions = append(questions, question)
	}
	return questions, nil
}
func UserQuestionsHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	username, ok := session.Values["username"].(string)
	if !ok {
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}

	questions, err := GetQuestionsByUser(username)
	if err != nil {
		handleInternalServerError(w, err)
		return
	}

	data := struct {
		Username  string
		Questions []Question
	}{
		Username:  username,
		Questions: questions,
	}

	if err := tmpl.ExecuteTemplate(w, "userquestions.html", data); err != nil {
		handleInternalServerError(w, err)
	}
}

func GetQuestionsByUserComments(username string) ([]Question, error) {
	db, err := sql.Open("sqlite3", "./Forum.db")
	if err != nil {
		return nil, fmt.Errorf("veritabanı bağlantısı sırasında hata oluştu: %v", err)
	}
	defer db.Close()

	query := `
        SELECT DISTINCT q.ID, q.Title, q.Description, q.Username, q.CreatedAt, q.Likes, q.Dislikes
        FROM Questions q
        JOIN Comments c ON q.ID = c.Question_id
        JOIN Users u ON c.User_id = u.ID
        WHERE u.KullaniciAdi = ?`
	rows, err := db.Query(query, username)
	if err != nil {
		return nil, fmt.Errorf("sorgu sırasında hata oluştu: %v", err)
	}
	defer rows.Close()

	var questions []Question
	for rows.Next() {
		var question Question
		if err := rows.Scan(&question.ID, &question.Title, &question.Description, &question.Username, &question.CreatedAt, &question.Likes, &question.Dislikes); err != nil {
			return nil, fmt.Errorf("satır tarama sırasında hata oluştu: %v", err)
		}

		// Her soru için yorumları al
		comments, err := GetCommentsForQuestion(question.ID)
		if err != nil {
			return nil, fmt.Errorf("yorumlar alınırken hata oluştu: %v", err)
		}
		question.Comments = comments

		questions = append(questions, question)
	}
	return questions, nil
}

func UserCommentedQuestionsHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	username, ok := session.Values["username"].(string)
	if !ok {
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}

	questions, err := GetQuestionsByUserComments(username)
	if err != nil {
		handleInternalServerError(w, err)
		return
	}

	data := struct {
		Username  string
		Questions []Question
	}{
		Username:  username,
		Questions: questions,
	}

	if err := tmpl.ExecuteTemplate(w, "QuestionComment.html", data); err != nil {
		handleInternalServerError(w, err)
	}
}
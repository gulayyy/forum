#node:latestı her zaman son sürümü alması için kullandık
FROM golang:latest

#çalışma dizenini belirlemek için kullanılır 
WORKDIR /app

RUN mkdir app

# Yerel kodu konteynere kopyala
COPY . .

# Go uygulamasını derle
RUN go build -o main .

# Uygulamanın çalıştığı portu aç
EXPOSE 8080

# Yürütülebilir dosyayı çalıştıran komut
CMD ["/app/main"]
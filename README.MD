FROM PROJESİ
Bu proje, kullanıcıların çeşitli konularda tartışmalar yapabileceği, mesaj gönderebileceği ve yorum yapabileceği bir forum uygulamasıdır. Aşağıda proje hakkında detaylı bilgiler ve kurulum talimatları bulunmaktadır.


ÖZELLİKLER

Kullanıcı Kaydı ve Girişi: Kullanıcılar e-posta ve şifre ile kayıt olabilir ve giriş yapabilir.

Konu Oluşturma ve Düzenleme: Kullanıcılar yeni konular oluşturabilir ve mevcut konuları düzenleyebilir.

Mesaj Gönderme ve Düzenleme: Kullanıcılar konulara mesaj gönderebilir ve gönderdikleri mesajları düzenleyebilir.

Yorum Yapma: Kullanıcılar mesajlara yorum yapabilir.

Beğenme ve Beğenmeme: Kullanıcılar mesajları beğenebilir veya beğenmeyebilir.

Kullanıcı Profilleri ve Ayarları: Kullanıcılar profil bilgilerini görüntüleyebilir ve düzenleyebilir.


Docker Konteynerları:
Docker, uygulama ve bağımlılıklarını bir araya getirip izole edilmiş bir ortamda çalıştırmak için konteyner teknolojisini kullanır. Bu, bir uygulamayı bir sistemden bağımsız olarak çalıştırmanın ve taşımanın bir yoludur.

Docker İmajları:
Docker imajları, bir konteynerın çalıştırılabilir bir versiyonunu tanımlayan temel yapı taşlarıdır. İmajlar, bir uygulamanın çalıştırılması için gerekli olan her şeyi içerir: kod, çalıştırma zamanı, sistem araçları, kütüphaneler ve bağımlılıklar.

Dockerfile:

Docker imajlarını oluşturmak için kullanılan metin dosyalarıdır. Dockerfile, bir uygulamanın imajını adım adım oluşturan talimatları içerir.
 
"docker image build -f Dockerfile -t <name_of_the_image> ."  ----> "DockerFile dosyamızda ki komutlar ve aldığı dosyalar ile  İmages larımıı oluşturmamızı sağlar 

"docker container run -p <port>:<port> --detach --name <name_of_the_container> <name_of_the_image>"  ---->  Konteynerımızı oluşturmamızı sağlar 

Uygulamamızın gerçekleşeceği portu  konteyner adı ve kullancağımız Images adını parametre olarak alacaktır 

"docker images"  ---> Imagesleri görüntülememizi sağlar 

" docker ps "  -----> Çalışan konteynerları gösterir 

" docker ps -a " -----> Hem Çalışan Hemde Durmuş Konteynerları gösterir

" docker images " -----> Imageslarımızı gösterir


" docker pull kullaniciAdi/imagesadi "  ----> Başka bir kişinin Imagesının kulanmamızı sağlar 

" docker exec -it <konteyner_adı veya konteyner_id> /bin/bash " ---> KOnteynerımızn terminaline erişmemizi sağlar 


" docker stop 'konteynerid' " ---> Çalışan konteynerı durdurmayı sağlar 

" docker start 'konteynerid' " ---> Durudurlan konteynerı çalıştırmamızı sağlar 

" docker pull 'kullanıcıadi/ımages' " ---> Başka birinin imagesını çekmemizi sağlar 

" docker rm 'konteynerid yada adi' " --> konteyner islmek için 

"docker rmi 'ımagesid'  "    ---> images silmek için 

" docker exec -it 'konteyneradi' /bin/bash "  --->  Çlaışan konteynerımıznı terminalinde olmamzı sağlar
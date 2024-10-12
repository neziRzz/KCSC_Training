

# Fibonacci (Đệ quy)
- Bài yêu cầu ta sử dụng đệ quy để tìm số Fibonacci thứ n. Ý tưởng thì khá đơn giản, ta chỉ cần gọi đệ quy hàm Fibonacci theo công thức `Fibonacci(n-1) + Fibonacci(n-2)` với trường hợp n > 1, khi n < 1 thì return lại n. Một điều cần phải lưu ý cho cách làm này là để tìm số Fibonacci cho n vô cùng lớn thì sẽ tốn rất nhiều thời gian vì bản chất của đệ quy. Hơn nữa các architecture x86/64 chỉ có giới hạn số trong khoảng int32 or int64 nên nếu số Fibonacci được return mà vượt quá khoảng này sẽ gây ra overflow, đồng thời nếu ta gọi đệ quy quá nhiều lần sẽ dẫn đến stack overflow bởi mỗi lần gọi hàm thì cho dù ta có push arguments cho hàm vào stack hay không thì mỗi một lần call thì địa chỉ return sau khi gọi hàm đều được push vào stack (bản chất của call instruction là 2 instructions push+jmp). Để giải quyết vấn đề này ta có 1 hướng làm khác chính là `Dynamic Programming` kết hợp với thuật toán `add 2 big num`.

# Fibonacci (Dynamic Programming)
- Như đã nói ở trên thì việc gọi đệ quy sẽ dẫn đến rất nhiều vấn đề như là về thời gian cũng như là có thể làm tràn stack. Nên ta có một giải pháp khác chính là `Dynamic Programming`. Như tên gọi, `Dynamic Programming` ở đây là ta sẽ sử dụng quy hoạch động (array hoặc malloc) để cấp phát vùng nhớ cho các Fibonacci sequence, điều này sẽ phần nào giải quyết được vấn đề thời gian so với việc sử dụng đệ quy bởi thuật toán này chỉ có time complexity là `O(n)` so với đệ quy `O(2^n)`, nhưng chỉ vậy thì ta vẫn chưa thể giải quyết được vấn đề khi mà n vô cùng lớn bởi giới hạn số của các architecture chỉ là 32/64 bits. Và để giải quyết vấn đề này, ta có thể sử dụng thuật toán `add 2 big nums`.

- Ý tưởng của thuật toán `add 2 big num` sẽ là ta coi 2 số này như là các string và thực hiện cộng từng digit của 2 số đó cho nhau (giống như cách ta nháp cộng trừ 2 số). Với thuật toán này ta sẽ không phải lo về overflow bởi độ lớn của kết quả bởi kết quả sẽ được lưu trữ dưới dạng string và ta có thể cấp phát kích thước phù hợp cho chúng bằng `malloc`

# RC4
- Bài này đơn thuần chỉ là code lại thuật toán RC4 bằng asm

# Base10 to any base
- Ý tưởng bài này sẽ là xây dựng stack bằng danh sách liên kết, với mỗi node của stack được malloc 8 byte (4 byte địa chỉ 4 byte data) or 16 byte (8 byte địa chỉ 8 byte data). Để đổi một số hệ 10 sang các hệ khác, ta chỉ cần lấy số hệ 10 đó chia cho hệ cần đổi cho đến khi không chia được nữa. Các phần dư của các phép tính đó khi lấy từ dưới lên sẽ là kết quả cần tìm, Ví dụ đổi số 11 sang hệ 2: 11/2 = 5 mod 1, 5/2 = 2 mod 1, 2/2 = 1 mod 0, 1/2 = 1 mod 1 -> 1011 (lấy dư từ cuối lên), với những hệ lớn hơn 10 thì ta gán cho các giá trị dư là từ A->F (10->15)

# Một số những lưu ý khi code MASM
- Câu lệnh invoke rất tiện nhưng không nên lạm dụng nhiều, ta chỉ dùng khi biết rõ các arguments được đẩy vào hàm là gì, dưới đây là ví dụ
```asm
push ebx (ebx = 1 for this example)
mov ebx, 5
invoke function , ebx
```
- Giả sử ta có intention là push giá trị 1 nằm trong ebx vào hàm `function` nhưng nếu để ý kĩ thì trước khi invoke function trên thì giá trị của ebx đã bị thay đổi thành 5, điều này có thể khiến cho hàm hoạt động sai và tệ hơn là crash chương trình, nên để hoàn toàn kiểm soát được những gì được truyền vào hàm, ta nên sử dụng instruction `call` truyền thống, bên dưới là ví dụ
```asm
push ebx
mov ebx, 5
call function
```
- Đặc biệt cẩn thận với những gì được push hay pop ra khỏi stack, bởi stack chứa rất nhiều những thông tin của các biến, địa chỉ return của các hàm,.... Một trong những practice sẽ là push những gì vào rồi thì phải pop hết chúng ra khi ra khỏi hàm và **theo thứ tự ngược lại**, ví dụ
```asm
function proc
  push ebp
  mov ebp, esp
  push esi
  push edx
  push ebx
.
.
.
.
  pop ebx
  pop edx
  pop esi
  pop ebp
  ret
```

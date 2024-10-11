#SUB TASK 02

## Fibonacci (Đệ quy)
- Bài yêu cầu ta sử dụng đệ quy để tìm số Fibonacci thứ n. Ý tưởng thì khá đơn giản, ta chỉ cần gọi đệ quy hàm Fibonacci theo công thức `Fibonacci(n-1) + Fibonacci(n-2)` với trường hợp n > 1, khi n < 1 thì return lại n. Một điều cần phải lưu ý cho cách làm này là để tìm số Fibonacci cho n vô cùng lớn thì sẽ tốn rất nhiều thời gian vì bản chất của đệ quy. Hơn nữa các architecture x86/64 chỉ có giới hạn số trong khoảng int32 or int64 nên nếu số Fibonacci được return mà vượt quá khoảng này sẽ gây ra overflow, đồng thời nếu ta gọi đệ quy quá nhiều lần sẽ dẫn đến stack overflow bởi mỗi lần gọi hàm thì cho dù ta có push arguments cho hàm vào stack hay không thì mỗi một lần call thì địa chỉ return sau khi gọi hàm đều được push vào stack (bản chất của call instruction). Để giải quyết vấn đề này ta có 1 hướng làm khác chính là `Dynamic Programming` kết hợp với thuật toán `add 2 big num`
## Fibonacci (Dynamic Programming)
- Như đã nói ở trên thì việc gọi đệ quy sẽ dẫn đến rất nhiều vấn đề như là về thời gian cũng như là có thể làm tràn stack. Nên ta có một giải pháp khác chính là `Dynamic Programming`. Như tên gọi, `Dynamic Programming` ở đây là ta sẽ sử dụng quy hoạch động (array hoặc malloc) để cấp phát vùng nhớ cho các Fibonacci sequence, điều này sẽ phần nào giải quyết được vấn đề thời gian so với việc sử dụng đệ quy bởi thuật toán này chỉ có time complexity là `O(n)` so với đệ quy `O(2^n)`, nhưng chỉ vậy thì ta vẫn chưa thể giải quyết được vấn đề khi mà n vô cùng lớn bởi giới hạn số của các architecture chỉ là 32/64 bits. Và để giải quyết vấn đề này, ta có thể sử dụng thuật toán `add 2 big nums`.


## RC4
## Base10 to any base

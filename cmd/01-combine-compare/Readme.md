# Gnarkabc: gnark流程的组合和对比


分别使用gnarkwrapper中对于groth16和plonk的wrapper，生成和验证一个简单电路的证明，并对比两者的性能。

```shell 
go build -o main
./main
```

浏览器打开生成的html文件即可观察性能对比结果
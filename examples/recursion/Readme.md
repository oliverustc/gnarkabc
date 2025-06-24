# Gnark recursion


阅读`https://github.com/Consensys/gnark/blob/master/std/recursion/groth16/verifier_test.go`中的代码可知，
目前允许的recursion组合包括：

| Inner Curve | Outer Curve |
| ----------- | ----------- |
| BN254       | BN254       |
| BLS12-377   | BW6-761     |
| BW6-761     | BN254       |

但是呢，无法处理BN254字符串到sw_bn254package名的映射。
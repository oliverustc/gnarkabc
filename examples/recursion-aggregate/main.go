package main

import "os"

func main() {
	args := os.Args[1:]
	switch args[0] {
	case "genleaf":
		GenerateLeafProof(16)
	case "ra1":
		RecursionAggregateLeafProofs([]int{0, 1, 2, 3, 4, 5, 6, 7}, 0)
		RecursionAggregateLeafProofs([]int{0, 2, 4, 6}, 1)
		RecursionAggregateLeafProofs([]int{0, 4}, 2)
	case "ra2":
		RecursionAggregateLeafProofs([]int{8, 9, 10, 11, 12, 13, 14, 15}, 0)
		RecursionAggregateLeafProofs([]int{8, 10, 12, 14}, 1)
		RecursionAggregateLeafProofs([]int{8, 12}, 2)
	}
}

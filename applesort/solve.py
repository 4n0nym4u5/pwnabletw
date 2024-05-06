import sys

MAX = 100000

dp = [-1] * (MAX + 1)


denomination = []


def countMinCoins(n, C, m):
    

    if (n == 0):
        dp[0] = 0
        return 0

    if (dp[n] != -1):
        return dp[n]


    ret = sys.maxsize

    for i in range(m):
        if (C[i] <= n):
            x = countMinCoins(n - C[i], C, m)


            if (x != sys.maxsize):
                ret = min(ret, 1 + x)

    
    dp[n] = ret
    return ret


def findSolution(n, C, m):
    
    # Base Case
    if (n == 0):


        for it in denomination:
            print(it, end = " ")

        return

    for i in range(m):

    
        if (n - C[i] >= 0 and
        dp[n - C[i]] + 1 == dp[n]):

            denomination.append(C[i])

    
            findSolution(n - C[i], C, m)
            break


def countMinCoinsUtil(X, C,N):
    
    isPossible = countMinCoins(X, C,N)

    
    if (isPossible == sys.maxsize):
        print("-1")

    
    else:
        findSolution(X, C, N)


if __name__ == '__main__':
    
    X = 7174

    
    arr = [ 199, 299, 399, 499 ]

    N = len(arr)

    # Function call
    countMinCoinsUtil(X, arr, N)
#include <NTL/ZZX.h>
#include <NTL/mat_ZZ.h>
#include <NTL/vector.h>
#include <time.h>

NTL_CLIENT

ZZ my_mod(ZZ a, ZZ q);//the new mod
ZZ assistant_algorithm(ZZ a, ZZ q);//the round-off of a/q
Vec<ZZX> SecretKeygen(long n);//SecretKeygen
ZZX gets_(Vec<ZZX> s);//get s'
mat_ZZ PublicKeygen(Vec<ZZX> s, ZZ q, long n);//PublicKeygen
ZZX getb(mat_ZZ A, long n);//get poly b
ZZX geta(mat_ZZ A, long n);//get poly a
Vec<ZZX> Enc(mat_ZZ A, ZZ q, long n, int msg);//Enc
ZZ Dec(Vec<ZZX> c, Vec<ZZX> s, ZZ q);//Dec

int main(void)
{
    long n;//the length n
    int msg;//the original message
    ZZ q, m;//the mod q and the decoded message m
    Vec<ZZX> s, c;//the sk -> s and the ciphertext -> c
    mat_ZZ A;//the pk -> A
    cout << "Please enter the number q : ";
    cin >> q;//get q
    cout << "\nPlease enter the number n : ";
    cin >> n;//get n
    s = SecretKeygen(n);//SecretKeygen
    cout << s;
    A = PublicKeygen(s, q, n);//PublicKeygen
    cout << "\nPlease enter the message : ";
    cin >> msg;//get the original message
    c = Enc(A, q, n, msg);//Enc
    cout << "\nc = " << c;
    m = Dec(c, s, q);//Dec
    cout << "\n\nThe decoded message is : "<< m;
    return 0;
}

ZZ my_mod(ZZ a, ZZ q)//the new mod
{
    return a - q * assistant_algorithm(a, q);
}

ZZ assistant_algorithm(ZZ a, ZZ q)//the round-off of a/q
{
    ZZ tmp;
    tmp = a * 10 / q;
    if (tmp % 10 >= 5)
    {
        return a / q + 1;
    }
    else
    {
        return a / q;
    }
}

Vec<ZZX> SecretKeygen(long n)//SecretKeygen
{
    Vec<ZZX> s;
    ZZX tmp, tmp0;
    int i;
    srand(time(NULL));
    s.SetLength(2);//set the length of the vector s
    SetCoeff(tmp0, 0, 1);//set the poly of s(1)
    s(1) = tmp0;
    for (i = 1; i < n + 1; i++)
    {
        SetCoeff(tmp, i, rand() % 3 - 1);//set the poly of s(2)
    }
    s(2) = -tmp;
    return s;//return s -> sk
}

ZZX gets_(Vec<ZZX> s)//get s'
{
    ZZX s_;
    s_ = -s(2);
    return s_;
}

mat_ZZ PublicKeygen(Vec<ZZX> s, ZZ q, long n)//PublicKeygen
{
    ZZX a, e1, s_, b;
    mat_ZZ A;
    int i;
    ZZ range(time(NULL));
    srand(time(NULL));
    for (i = 0; i < n; i++)
    {
        SetCoeff(a, i, my_mod(RandomBnd(range), q));//set the poly a
        SetCoeff(e1, i, rand() % 3 - 1);//set the poly e1
    }
    s_ = gets_(s);//get s'
    b = MulTrunc(a, s_, n) + e1;//b = a * s' + e1
    for (i = 0; i < n; i++)
    {
        SetCoeff(b, i, my_mod(b[i], q));//set the poly b
    }
    A.SetDims(n, 2);//set the rank of the matrix A
    for (i = 0; i < n; i++)//assign to the matrix A
    {
        A[i][0] = b[i];
        A[i][1] = a[i];
    }
    return A;//return A -> pk
}

ZZX getb(mat_ZZ A, long n)//get poly b
{
    int i;
    ZZX b;
    for (i = 0; i < n; i++)
    {
        SetCoeff(b, i, A[i][0]);
    }
    return b;
}

ZZX geta(mat_ZZ A, long n)//get poly a
{
    int i;
    ZZX a;
    for (i = 0; i < n; i++)
    {
        SetCoeff(a, i, A[i][1]);
    }
    return a;
}

Vec<ZZX> Enc(mat_ZZ A, ZZ q, long n, int msg)//Enc
{
    ZZX m, e2, e3, e4, a, b, tmp1, tmp2;
    Vec<ZZX> c;
    SetCoeff(m, 0, msg);//set the original message as the constant
    int i;
    srand(time(NULL));
    for (i = 1; i < n; i++)
    {
        SetCoeff(m, i, rand() % 2);//set the poly m
    }
    for (i = 0; i < n; i++)
    {
        SetCoeff(e2, i, rand() % 3 - 1);//set the poly e2
        SetCoeff(e3, i, rand() % 3 - 1);//set the poly e3
        SetCoeff(e4, i, rand() % 3 - 1);//set the poly e4
    }
    a = geta(A, n);//get the poly a
    b = getb(A, n);//get the poly b
    tmp1 = MulTrunc(b, e2, n) + e3 + (q / 2) * m;
    tmp2 = MulTrunc(a, e2, n) + e4;
    for (i = 0; i < n; i++)
    {
        SetCoeff(tmp1, i, my_mod(tmp1[i], q));
        SetCoeff(tmp2, i, my_mod(tmp2[i], q));
    }
    c.SetLength(2);
    c(1) = tmp1;//assign to the vector c
    c(2) = tmp2;
    return c;//return c -> ciphertext
}

ZZ Dec(Vec<ZZX> c, Vec<ZZX> s, ZZ q)//Dec
{
    ZZX tmp = c(1) * s(1) + c(2) * s(2);
    ZZ m = tmp[0];
    m = assistant_algorithm(my_mod(m, q) * 2, q) % 2;
    return m;//return m -> the decoded message
}

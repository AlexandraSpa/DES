// cripto_tema3.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
using namespace std;

int plaintext[64], ciphertext[64], K[64], subkey[17][48], C[28], D[28], LPT[32], RPT[32], S_boxresult[32];

int PC1_m[56] = 
{ 57, 49, 41, 33, 25, 17, 9,
1, 58, 50, 42, 34, 26, 18,
10, 2, 59, 51, 43, 35, 27,
19, 11, 3, 60, 52, 44, 36,
63, 55, 47, 39, 31, 23, 15,
7, 62, 54, 46, 38, 30, 22,
14, 6, 61, 53, 45, 37, 29,
21, 13, 5, 28, 20, 12, 4 };
int PC2_m[56] =
{ 14, 17, 11, 24, 1, 5,
3, 28, 15, 6, 21, 10,
23, 19, 12, 4, 26, 8,
16, 7, 27, 20, 13, 2,
41, 52, 31, 37, 47, 55,
30, 40, 51, 45, 33, 48,
44, 49, 39, 56, 34, 53,
46, 42, 50, 36, 29, 32 };
int IP_m[64] =
{ 58, 50, 42, 34, 26, 18, 10, 2,
60, 52, 44, 36, 28, 20, 12, 4,
62, 54, 46, 38, 30, 22, 14, 6,
64, 56, 48, 40, 32, 24, 16, 8,
57, 49, 41, 33, 25, 17, 9, 1,
59, 51, 43, 35, 27, 19, 11, 3,
61, 53, 45, 37, 29, 21, 13, 5,
63, 55, 47, 39, 31, 23, 15, 7
};
int E_m[48] =
{
    32, 1, 2, 3, 4, 5,
 4, 5, 6, 7, 8, 9,
 8, 9, 10, 11, 12, 13,
12, 13, 14, 15, 16, 17,
16, 17, 18, 19, 20, 21,
20, 21, 22, 23, 24, 25,
24, 25, 26, 27, 28, 29,
28, 29, 30, 31, 32, 1
};
int S1_m[4][16] = { { 14,  4,  13,  1,   2, 15,  11,  8,   3, 10,   6, 12,   5,  9,   0,  7 },
                 { 0,  15,   7,  4,  14,  2,  13,  1,  10,  6,  12, 11,   9,  5,   3,  8},
                  { 4,  1,  14,  8,  13,  6,   2, 11,  15, 12,   9,  7,   3, 10,   5,  0},
                  { 15, 12,   8,  2,   4,  9,   1,  7,   5, 11,   3, 14,  10,  0,   6, 13},
};

int S2_m[4][16] = { { 15,  1,   8, 14,   6, 11,   3,  4,   9,  7,   2, 13,  12,  0,   5, 10 },
                 {  3, 13,   4,  7,  15,  2,   8, 14,  12,  0,   1, 10,   6,  9,  11,  5},
                  { 0, 14,   7, 11,  10,  4,  13,  1,   5,  8,  12,  6,   9,  3,  2, 15},
                  { 13,  8,  10,  1,   3, 15,   4,  2,  11,  6,   7, 12,   0,  5,  14,  9}
};

int S3_m[4][16] = { {10,  0,   9, 14,   6,  3 , 15 , 5  , 1, 13,  12,  7,  11,  4 ,  2,  8},
     {13,  7,   0,  9,   3,  4,   6, 10,   2,  8,   5, 14,  12, 11,  15,  1},
     {13,  6,   4,  9,   8, 15,   3,  0,  11,  1,   2, 12,   5, 10,  14,  7},
      {1, 10,  13,  0,   6,  9,   8,  7,   4, 15,  14 , 3 , 11,  5 ,  2, 12}
};


int S4_m[4][16] = { {7, 13,  14,  3,   0 , 6,   9, 10,   1 , 2,   8, 5,  11, 12,   4 ,15},
     {13,  8,  11,  5 ,  6 ,15 ,  0 , 3 ,  4,  7,   2, 12 ,  1 ,10,  14 , 9},
     {10,  6,   9,  0,  12, 11,   7, 13,  15,  1,   3, 14,   5,  2,   8,  4},
      {3, 15 ,  0,  6,  10,  1,  13,  8 ,  9 , 4 ,  5, 11,  12 , 7 ,  2 ,14} };

int S5_m[4][16] = { {2, 12,   4 , 1,   7, 10 , 11,  6,   8 , 5,   3, 15,  13,  0,  14,  9},
     {14, 11,   2, 12,   4,  7,  13,  1 ,  5 , 0,  15, 10,   3,  9 ,  8 , 6},
     { 4,  2,   1, 11,  10, 13,   7,  8 , 15,  9,  12,  5,   6,  3,   0, 14},
     {11,  8,  12,  7,   1, 14,   2, 13,   6, 15,   0 , 9,  10 , 4  , 5 , 3} };

int S6_m[4][16] = { {12,  1,  10, 15,   9 , 2,   6,  8,   0, 13,   3,  4,  14,  7 ,  5, 11},
     {10, 15,   4,  2 ,  7 ,12 ,  9,  5,   6,  1,  13, 14,   0, 11 ,  3  ,8},
     { 9, 14,  15,  5,   2 , 8,  12,  3 ,  7 , 0 ,  4, 10  , 1, 13 , 11 , 6},
     { 4,  3,   2, 12,   9,  5,  15, 10,  11, 14 ,  1,  7,   6,  0,   8, 13}
};

int S7_m[4][16] = { {4, 11 ,  2 ,14 , 15 , 0 ,  8 ,13 ,  3, 12 ,  9,  7 ,  5 ,10,   6,  1},
     {13,  0,  11 , 7  , 4 , 9 ,  1, 10 , 14 , 3 ,  5 ,12 ,  2 ,15 ,  8,  6},
     { 1,  4  ,11, 13,  12,  3,   7 ,14,  10 ,15,   6,  8  , 0,  5,   9,  2},
     { 6 ,11 , 13 , 8  , 1 , 4,  10 , 7,   9,  5 ,  0 ,15 , 14  ,2 ,  3, 12}
};

int S8_m[4][16] = { { 13,  2,   8 , 4 ,  6 ,15 , 11 , 1  ,10 , 9 ,  3 ,14,   5 , 0 , 12 , 7},
     { 1 ,15,  13 , 8 , 10,  3 ,  7 , 4,  12,  5  , 6 ,11 ,  0 ,14 ,  9,  2},
     { 7, 11 ,  4,  1 ,  9, 12 , 14 , 2,   0,  6 , 10 ,13 , 15 , 3 ,  5 , 8},
     { 2,  1,  14,  7 ,  4, 10 ,  8 ,13,  15, 12 ,  9  ,0 ,  3 , 5 ,  6, 11}
};

int P_m[32] =
{ 16, 7, 20, 21,
29, 12, 28, 17,
1, 15, 23, 26,
5, 18, 31, 10,
2, 8, 24, 14,
32, 27, 3, 9,
19, 13, 30, 6,
22, 11, 4, 25
};

int IPreverse[64] = { 40,   8,  48,    16,    56,   24,    64,   32,
                       39,     7,   47,    15,    55,   23,    63,   31,
                       38,     6,   46,    14,    54,   22,    62,   30,
                        37,     5,  45,    13,    53,   21,    61,   29,
                        36,     4,   44,    12,    52,   20,    60,   28,
                        35,     3,   43,    11,    51,   19,    59,   27,
                      34,     2,   42,    10,    50,   18,    58,   26,
                       33,     1,   41,     9,    49,   17,    57,   25};

void PC_1(int key[])
{
    int aux[64];
    for (int i = 0; i <= 55; i++)
    {
        aux[i] = key[PC1_m[i]-1];
    }
    for (int i = 0; i <= 55; i++)
    {
        key[i] = aux[i];
    }
    for (int i = 56; i < 64; i++)
    {
        key[i] = -1;
    }
    for (int i = 0; i < 28; i++)
    {
        C[i] = key[i];
        D[i] = key[i + 28];
    }

}
void PC_2(int no) 
{//modifica, elimina aux, e degeaba
    int aux[48];
    int CD[56];
    for (int i = 0; i < 28; i++)
    {
        CD[i]= C[i];
        CD[i+28]= D[i];
    }
    for (int i = 0; i < 48; i++)
    {
        aux[i] = CD[PC2_m[i] - 1];
    }
    //aux este subkey ul no generat
    
    for (int i = 0; i < 48; i++)
    {
        subkey[no][i] = aux[i];
    }
}

void LS(int half[28])
{
    int first_element = half[0];
    for (int i = 0; i < 27; i++)
    {
        half[i] = half[i + 1];
    }
    half[27] = first_element;
}

void key_transformation(int key[])
{
    PC_1(key);
}
void generate_subkey(int no)
{
    switch (no)
    {
    case 1:
    case 2:
    case 9:
    case 16:
        LS(C);
        LS(D);
        break;
    default:
        LS(C);
        LS(C);
        LS(D);
        LS(D);
    }
    /*if (no == 1 || no == 2 || no == 9 || no == 16)
    {


    }
     */
    PC_2(no);
}

void initial_permutation()
{
    int aux[64];
    for (int i = 0; i < 64; i++)
    {
        aux[i] = plaintext[IP_m[i] - 1];
    }
    for (int i = 0; i < 64; i++)
    {
        plaintext[i] = aux[i];
    }
    for (int i = 0; i < 32 ; i++)
    {
        LPT[i] = plaintext[i];
        RPT[i] = plaintext[i+32];
    }


}
void S_1(int pack[6])
{
    int line, column, number;
    line = pack[0] * 2 + pack[5];
    column = pack[1]*8 + pack[2]*4 + pack[3]*2 + pack[4];
    number = S1_m[line][column];
    S_boxresult[0] = number % 2;
    number %= 2;
    S_boxresult[1] = number % 2;
    number %= 2;
    S_boxresult[2] = number % 2;
    number %= 2;
    S_boxresult[3] = number % 2;

}
void S_2(int pack[6])
{
    int line, column, number;
    line = pack[0] * 2 + pack[5];
    column = pack[1] * 8 + pack[2] * 4 + pack[3] * 2 + pack[4];
    number = S2_m[line][column];
    S_boxresult[4] = number % 2;
    number %= 2;
    S_boxresult[5] = number % 2;
    number %= 2;
    S_boxresult[6] = number % 2;
    number %= 2;
    S_boxresult[7] = number % 2;

}
void S_3(int pack[6])
{
    int line, column, number;
    line = pack[0] * 2 + pack[5];
    column = pack[1] * 8 + pack[2] * 4 + pack[3] * 2 + pack[4];
    number = S3_m[line][column];
    S_boxresult[8] = number % 2;
    number %= 2;
    S_boxresult[9] = number % 2;
    number %= 2;
    S_boxresult[10] = number % 2;
    number %= 2;
    S_boxresult[11] = number % 2;

}
void S_4(int pack[6])
{
    int line, column, number;
    line = pack[0] * 2 + pack[5];
    column = pack[1] * 8 + pack[2] * 4 + pack[3] * 2 + pack[4];
    number = S4_m[line][column];
    S_boxresult[12] = number % 2;
    number %= 2;
    S_boxresult[13] = number % 2;
    number %= 2;
    S_boxresult[14] = number % 2;
    number %= 2;
    S_boxresult[15] = number % 2;

}
void S_5(int pack[6])
{
    int line, column, number;
    line = pack[0] * 2 + pack[5];
    column = pack[1] * 8 + pack[2] * 4 + pack[3] * 2 + pack[4];
    number = S4_m[line][column];
    S_boxresult[16] = number % 2;
    number %= 2;
    S_boxresult[17] = number % 2;
    number %= 2;
    S_boxresult[18] = number % 2;
    number %= 2;
    S_boxresult[19] = number % 2;
}
void S_6(int pack[6])
{
    int line, column, number;
    line = pack[0] * 2 + pack[5];
    column = pack[1] * 8 + pack[2] * 4 + pack[3] * 2 + pack[4];
    number = S4_m[line][column];
    S_boxresult[20] = number % 2;
    number %= 2;
    S_boxresult[21] = number % 2;
    number %= 2;
    S_boxresult[22] = number % 2;
    number %= 2;
    S_boxresult[23] = number % 2;
}
void S_7(int pack[6])
{
    int line, column, number;
    line = pack[0] * 2 + pack[5];
    column = pack[1] * 8 + pack[2] * 4 + pack[3] * 2 + pack[4];
    number = S4_m[line][column];
    S_boxresult[24] = number % 2;
    number %= 2;
    S_boxresult[25] = number % 2;
    number %= 2;
    S_boxresult[26] = number % 2;
    number %= 2;
    S_boxresult[27] = number % 2;
}
void S_8(int pack[6])
{
    int line, column, number;
    line = pack[0] * 2 + pack[5];
    column = pack[1] * 8 + pack[2] * 4 + pack[3] * 2 + pack[4];
    number = S4_m[line][column];
    S_boxresult[28] = number % 2;
    number %= 2;
    S_boxresult[29] = number % 2;
    number %= 2;
    S_boxresult[30] = number % 2;
    number %= 2;
    S_boxresult[31] = number % 2;
}
void expansion(int half[32], int result[48])
{
    int aux[48];
    for (int i = 0; i < 48; i++)
    {
        aux[i] = half[E_m[i] - 1];
    }
    for (int i = 0; i < 48; i++)
    {
        result[i] = aux[i];
    }

}
void P_permutation(int s_boxoutput[32])
{
    int aux[48];
    for (int i = 0; i < 32; i++)
    {
        aux[i] = s_boxoutput[P_m[i] - 1];
    }
    for (int i = 0; i < 32; i++)
    {
        s_boxoutput[i] = aux[i];
    }
}
void cipher_function(int no, int m_result[32])
{
    int S1[6], S2[6], S3[6], S4[6], S5[6], S6[6], S7[6], S8[6];
    int RPTextended[64], XORresult[48];
    expansion(RPT, RPTextended);
    //XOR
    for (int i = 0; i < 48; i++)
    {
        if (RPTextended[i] == subkey[no][i])
        {
            XORresult[i] = 0;
        }
        else
        {
            XORresult[i] = 1;
        }
    }
    for (int i = 0; i < 6; i++)
    {
        S1[i] = XORresult[i];
        S2[i]= XORresult[i+6];
        S3[i] = XORresult[i + 12];
        S4[i] = XORresult[i + 18];
        S5[i] = XORresult[i + 24];
        S6[i] = XORresult[i + 30];
        S7[i] = XORresult[i + 36];
        S8[i] = XORresult[i + 42];
    }
    S_1(S1);
    S_2(S2);
    S_3(S3);
    S_4(S4);
    S_5(S5);
    S_6(S6);
    S_7(S7);
    S_8(S8);
    // now the S_boxresult array is populated
    P_permutation(S_boxresult);
    for (int i = 0; i < 32; i++)
    {
        m_result[i]= S_boxresult[i];
    }
}

void do_round(int no)
{
    int cipher_result[32], XORresult[32];
    generate_subkey(no);
    cipher_function(no, cipher_result);
    //XOR
    //XOR
    for (int i = 0; i < 32; i++)
    {
        if (LPT[i] == cipher_result[i])
        {
            XORresult[i] = 0;
        }
        else
        {
            XORresult[i] = 1;
        }
    }
    cout << endl;
    cout << "Results of round " << no << ": ";
    cout << endl;
    cout << "LPT: ";
    for (int i = 0; i < 32; i++)
    {
        LPT[i] = RPT[i];
        cout << LPT[i] << " ";
    }
    cout << endl;
    cout << "RPT: ";
    for (int i = 0; i < 32; i++)
    {
       RPT[i] = XORresult[i];
       cout << RPT[i] << " ";
    }
    cout << endl;
    
}
void do_round2(int no)
{
    int cipher_result[32], XORresult[32];
    //generate_subkey(no);
    cipher_function(no, cipher_result);
    //XOR
    //XOR
    for (int i = 0; i < 32; i++)
    {
        if (LPT[i] == cipher_result[i])
        {
            XORresult[i] = 0;
        }
        else
        {
            XORresult[i] = 1;
        }
    }
    cout << endl;
    cout << "Results of round " << no << ": ";
    cout << endl;
    cout << "LPT: ";
    for (int i = 0; i < 32; i++)
    {
        LPT[i] = RPT[i];
        cout << LPT[i] << " ";
    }
    cout << endl;
    cout << "RPT: ";
    for (int i = 0; i < 32; i++)
    {
        RPT[i] = XORresult[i];
        cout << RPT[i] << " ";
    }
    cout << endl;

}
void final_permutation()
{
    for (int i = 0; i < 32; i++)
    {
        ciphertext[i] = RPT[i];
        ciphertext[i + 32] = LPT[i];
    }

    int aux[64];
    for (int i = 0; i < 64; i++)
    {
        aux[i] = ciphertext[IPreverse[i] - 1];
    }
    for (int i = 0; i < 64; i++)
    {
       ciphertext[i] = aux[i];
    }

}

int main()
{
    cout << "Introduce the key: ";
    cout << endl;
    for (int i = 0; i <= 63; i++)
    {
        cin >> K[i];
    }
    key_transformation(K);

    cout << "Introduce the plaintext: ";
    cout << endl;
    for (int i = 0; i <= 63; i++)
    {
        cin >> plaintext[i];
    }
    initial_permutation();
    int contor = 1;
    while(contor <= 16)
    {
        do_round(contor);
        contor++;
    }
    final_permutation();
    cout << "The cipher text is: ";
    cout << endl;
    for (int i = 0; i <= 63; i++)
    {
        cout << ciphertext[i] << " ";
    }

    //Decryption part
    int plaintextoriginal[64];
    for (int i = 0; i <= 63; i++)
    {
        plaintextoriginal[i] = plaintext[i];
    }
    for (int i = 0; i <= 63; i++)
    {
        plaintext[i] = ciphertext[i];
    }

    initial_permutation();
    contor = 16;
    while (contor >= 1)
    {
        do_round2(contor);
        contor--;
    }
    final_permutation();

    cout << "The decripted text is: ";
    cout << endl;
    for (int i = 0; i <= 63; i++)
    {
        cout << ciphertext[i] << " ";
    }

    /*generate_subkey(1);

    cout<<"The main key without the parity bits is : "<<endl;
    for (int i = 0; i <= 63; i++)
    {
        cout << K[i] << " ";
        if ((i+1) % 7 == 0)
        {
            cout << endl;
        }
    } 
    cout << endl;

    cout << "The C half is: " << endl;
    for (int i = 0; i < 28; i++)
    {
        cout << C[i] << " ";
        if ((i + 1) % 7 == 0)
        {
            cout << endl;
        }
    }

    cout << endl;

    cout << "The D half is: " << endl;
    for (int i = 0; i < 28; i++)
    {
        cout << D[i] << " ";
        if ((i + 1) % 7 == 0)
        {
            cout << endl;
        }
    }

    cout << endl;

    cout << "The subkey no 1 generated is: " << endl;
    for (int i = 0; i < 48; i++)
    {
        cout << subkey[1][i] << " ";
        if ((i + 1) % 6 == 0)
        {
            cout << endl;
        }
    }

    cout << endl;

    generate_subkey(2);

    cout << "The C half is: " << endl;
    for (int i = 0; i < 28; i++)
    {
        cout << C[i] << " ";
        if ((i + 1) % 7 == 0)
        {
            cout << endl;
        }
    }

    cout << endl;

    cout << "The D half is: " << endl;
    for (int i = 0; i < 28; i++)
    {
        cout << D[i] << " ";
        if ((i + 1) % 7 == 0)
        {
            cout << endl;
        }
    }

    cout << endl;

    cout << "The subkey no 2 generated is: " << endl;
    for (int i = 0; i < 48; i++)
    {
        cout << subkey[2][i] << " ";
        if ((i + 1) % 6 == 0)
        {
            cout << endl;
        }
    }

    cout << endl;

    generate_subkey(3);

    cout << "The C half is: " << endl;
    for (int i = 0; i < 28; i++)
    {
        cout << C[i] << " ";
        if ((i + 1) % 7 == 0)
        {
            cout << endl;
        }
    }

    cout << endl;

    cout << "The D half is: " << endl;
    for (int i = 0; i < 28; i++)
    {
        cout << D[i] << " ";
        if ((i + 1) % 7 == 0)
        {
            cout << endl;
        }
    }

    cout << endl;

    cout << "The subkey no 3 generated is: " << endl;
    for (int i = 0; i < 48; i++)
    {
        cout << subkey[3][i] << " ";
        if ((i + 1) % 6 == 0)
        {
            cout << endl;
        }
    }

    cout << endl;
    */
}
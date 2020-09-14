#include "pRNG.h"
#include <Arduino.h>

uint16_t Firstprime, Secondprime, Privatekey, Publickey;
uint32_t Field, phin, Enc, Dec;
bool Hasrun= false;
uint16_t Text = 123;


pRNG prn;

uint32_t modMult(uint16_t a, uint16_t b, uint16_t mod) //modulo multiplication function
{ 
    uint32_t res = 0; // Initialize result 
  
    // Update a if it is more than 
    // or equal to mod 
    a %= mod; 
  
    while (b) 
    { 
        // If b is odd, add a with result 
        if (b & 1) 
            res = (res + a) % mod; 
  
        // Here we assume that doing 2*a 
        // doesn't cause overflow 
        a = (2 * a) % mod; 
  
        b >>= 1; // b = b / 2 
    } 
  
    return res; 
} 
bool primality(uint16_t number) //primality check for prime numbers
{
   
     for (uint16_t i = 2; i <=sqrt(number); ++i) 
        {
            if (number % i == 0) 
            {
                return false;
            }
         }
        return true;
  }
  

uint16_t PRN()   //generation of a prime random number
{
 uint16_t n1;
  do
  { 
    n1= prn.getRndInt();
   }while(primality(n1)==false); 
   return n1;
}
uint16_t gcd(uint16_t a, uint16_t b) //function to check GCD
{ 
    uint16_t temp; 
    while (1) 
    { 
        temp = a%b; 
        if (temp == 0) 
         return b; 

       a = b; 
       b= temp;
         
    } 
} 
uint32_t E_gen(uint32_t n, uint32_t phi)   //publickey generation e
{
    for(uint32_t i=2; i<n; i++)
     {
       if(gcd(i,n)==1 && gcd(i,phi)==1)
       {
         return i;
         //break;
       }
        
     }
   Serial.println("Public key generated");
 }

uint32_t D_gen(uint32_t en, uint32_t phi) //privatekey generation d
{
  for(uint32_t i=2; i<phi; i++)
  {
    if(modMult(en,i,phi)==1)
    {
      return i;
      //break;
    }
     
  }
   Serial.println("Private key generated");
  }
uint32_t power(uint16_t base, uint32_t expo, uint32_t mod)  
{  
    
    uint32_t result = 1;
    while ( expo > 0)
    {
        if (expo % 2 == 1)
            result = (result * base) % mod;
        expo = expo >> 1;
        base = (base * base) % mod;
    }
    return result;  
} 
 /*uint16_t keygen()
 {
  
  
 }*/
void setup()
{
   Serial.begin(9600);
    Firstprime=PRN();
   Serial.println(Firstprime);
   do
   {  
   Secondprime=PRN();
   Serial.println(Secondprime);
   }while(Firstprime==Secondprime); 
  Field=Firstprime*Secondprime;
  phin=(Firstprime-1)*(Secondprime-1);
  
  
}

void loop()
{
  if(Hasrun==false)
  {
     //Serial.println(prn.getRnduint16_t());
    Publickey=E_gen(Field, phin);
    Privatekey=D_gen(Publickey,phin);
    Serial.print("Public key is:");
    Serial.println(Publickey);
    Serial.print("Private key is:");
    Serial.println(Privatekey);
    Serial.println("Encrypting....");
    Enc= power(Text,Publickey, Field);
    Serial.println(Enc);
    Serial.println("Decrypting...");
    Dec=power(Enc,Privatekey, Field);
    Serial.println(Dec);
    /*Serial.println(p);
    Serial.println(q);*/

    Hasrun=true;
      
  }
}

#include <Arduino.h>

/*
    Initializing all states, contants, and functions.
*/
enum clientState {
    START, WAITING_FOR_ACK, C_DATA_EXCHANGE 
};

enum serverState {
    LISTEN, WAITING_FOR_KEY, WAIT_FOR_ACK, S_DATA_EXCHANGE
};

const int serverPin = 13;

bool isServer();
uint32_t multMod(uint32_t a, uint32_t b, uint32_t m);
uint32_t powMod(uint32_t a, uint32_t b, uint32_t m);
void uint32_to_serial3(uint32_t num);
uint32_t uint32_from_serial3();
uint32_t encrypt(char c, uint32_t e, uint32_t m);
char decrypt(uint32_t x, uint32_t d, uint32_t n);
void communication(uint32_t d, uint32_t n, uint32_t e, uint32_t m);
bool primality(uint32_t number);
int32_t reduce_mod(int32_t x, uint32_t m);
uint32_t generate_d(uint32_t e, uint32_t phi_n);
uint32_t gcd_euclid_fast(uint32_t a, uint32_t b);
uint32_t num_gen(uint32_t bits);
uint32_t prime_gen(uint32_t bits);
uint32_t generate_e(uint32_t phi_n);
void handshakeServer(uint32_t& serverPrivateKey, uint32_t& smod, uint32_t& ckey , uint32_t& cmod);
void handshakeClient(uint32_t& clientPrivateKey, uint32_t& cmod, uint32_t& skey, uint32_t& smod);
bool wait_on_serial3(uint8_t nbytes, long timeout);
void generate_keys(uint32_t& e, uint32_t& d, uint32_t& n);

/*
    Performs basic Arduino setup tasks.
*/
void setup() {
    init();
    Serial.begin(9600);
    Serial3.begin(9600);

    Serial.println("Welcome to Arduino Chat!");
}


/*
    The entry point to our program.
*/
int main() {
    setup();
    uint32_t d, n, e, m;

    // Determine our role and the encryption keys.
    if (isServer()) {
        Serial.println("Server");
        handshakeServer(d, n, e, m);
    } else {
        Serial.println("Client");
        handshakeClient(d, n, e, m);
    }

    // Print out keys
    Serial.print("This Arduino's Public Key is: ");
    Serial.println(e);
    Serial.print("This Arduino's Modulus is: ");
    Serial.println(m);

    // Now enter the communication phase.
    communication(d, n, e, m);

    //Flusing 
    Serial.flush();
    Serial3.flush();

    // Should never get this far (communication has an infite loop).
    return 0;
}


/*
    Core communication loop
    d, n, e, and m are according to the assignment spec
*/
void communication(uint32_t d, uint32_t n, uint32_t e, uint32_t m) {
    // Consume all early content from Serial3 to prevent garbage communication
    while (Serial3.available()) {
        Serial3.read();
    }

    // Enter the communication loop
    while (true) {
        // Check if the other Arduino sent an encrypted message.
        if (Serial3.available() >= 4) {
            // Read in the next character, decrypt it, and display it
            uint32_t read = uint32_from_serial3();
            Serial.print(decrypt(read, d, n));
        }

        // Check if the user entered a character.
        if (Serial.available() >= 1) {
            char byteRead = Serial.read();
            // Read the character that was typed, echo it to the serial monitor,
            // and then encrypt and transmit it.
            if ((int) byteRead == '\r') {
                // If the user pressed enter, we send both '\r' and '\n'
                Serial.print('\r');
                uint32_to_serial3(encrypt('\r', e, m));
                Serial.print('\n');
                uint32_to_serial3(encrypt('\n', e, m));
            } else {
                Serial.print(byteRead);
                uint32_to_serial3(encrypt(byteRead, e, m));
            }
        }
    }
}


/*
    Returns true if arduino is server, false if arduino is client
*/
bool isServer() {
    if (digitalRead(serverPin) == HIGH) {
        return true;
    } else {
        return false;
    }
}

/*
    Compute and return (a*b)%m
    Note: m must be less than 2^31
    Arguments:
        a (uint32_t): The first multiplicant
        b (uint32_t): The second multiplicant
        m (uint32_t): The mod value
    Returns:
        result (uint32_t): (a*b)%m
*/
uint32_t multMod(uint32_t a, uint32_t b, uint32_t m) {
    uint32_t result = 0;
    uint32_t dblVal = a%m;
    uint32_t newB = b;

    // This is the result of working through the worksheet.
    // Notice the extreme similarity with powmod.
    while (newB > 0) {
        if (newB & 1) {
            result = (result + dblVal) % m;
        }
        dblVal = (dblVal << 1) % m;
        newB = (newB >> 1);
    }

    return result;
}


/*
    NOTE: This was modified using our multMod function, but is otherwise the
    function powModFast provided in the lectures.

    Compute and return (a to the power of b) mod m.
      Example: powMod(2, 5, 13) should return 6.
*/
uint32_t powMod(uint32_t a, uint32_t b, uint32_t m) {
    uint32_t result = 1 % m;
    uint32_t sqrVal = a % m;  // stores a^{2^i} values, initially 2^{2^0}
    uint32_t newB = b;

    // See the lecture notes for a description of why this works.
    while (newB > 0) {
        if (newB & 1) {  // evalutates to true iff i'th bit of b is 1 in the i'th iteration
            result = multMod(result, sqrVal, m);
        }
        sqrVal = multMod(sqrVal, sqrVal, m);
        newB = (newB >> 1);
    }

    return result;
}



/** Writes an uint32_t to Serial3, starting from the least-significant
 * and finishing with the most significant byte.
 */
void uint32_to_serial3(uint32_t num) {
    Serial3.write((char) (num >> 0));
    Serial3.write((char) (num >> 8));
    Serial3.write((char) (num >> 16));
    Serial3.write((char) (num >> 24));
}


/** Reads an uint32_t from Serial3, starting from the least-significant
 * and finishing with the most significant byte.
 */
uint32_t uint32_from_serial3() {
    uint32_t num = 0;
    num = num | ((uint32_t) Serial3.read()) << 0;
    num = num | ((uint32_t) Serial3.read()) << 8;
    num = num | ((uint32_t) Serial3.read()) << 16;
    num = num | ((uint32_t) Serial3.read()) << 24;
    return num;
}


/*
    Encrypts using RSA encryption.

    Arguments:
        c (char): The character to be encrypted
        e (uint32_t): The partner's public key
        m (uint32_t): The partner's modulus

    Return:
        The encrypted character (uint32_t)
*/
uint32_t encrypt(char c, uint32_t e, uint32_t m) {
    return powMod(c, e, m);
}


/*
    Decrypts using RSA encryption.

    Arguments:
        x (uint32_t): The communicated integer
        d (uint32_t): The Arduino's private key
        n (uint32_t): The Arduino's modulus

    Returns:
        The decrypted character (char)
*/
char decrypt(uint32_t x, uint32_t d, uint32_t n) {
    return (char) powMod(x, d, n);
}


// Function to test for prime numbers.
bool primality(uint32_t number) {
    if (number == 0 || number == 1) {
        return false;
    }
    else {
        for (int i = 2, sqrtNum = sqrt(number); i < sqrtNum; ++i) {
            if (number % i == 0) {
                return false;
            }
        }
        return true;
    }
}


// Given an integer x, possibly negative, return an integer
// in the range 0..m-1 that is congruent to x (mod m)
int32_t reduce_mod(int32_t x, uint32_t m) {
    uint32_t rem = x % m;
    if (rem < 0) {
        rem += m;
    }
    return rem;
}


// Find a d such that e·d ≡ 1 (mod φ(n)) or declares fail
uint32_t generate_d(uint32_t e, uint32_t phi_n) {
    if (gcd_euclid_fast(e, phi_n) != 1) {
        return 1; //FAIL
    }
    else {
        // Find an integer d such that (e*d) == 1 (mod phi_n)
        uint32_t q, r[40], s[40], t[40];
        r[0] = e; r[1] = phi_n;
        s[0] = 1; s[1] = 0;
        t[0] = 0; t[1] = 1;
        
        uint32_t i = 1;
        while (r[i] > 0) {
            q = r[i-1] / r[i];
            r[i+1] = r[i-1] - q*r[i];
            s[i+1] = s[i-1] - q*s[i];
            t[i+1] = t[i-1] - q*t[i];
            ++i;
        }
        uint32_t d = s[i-1];
        
        if (d < 0 || d >= phi_n) {
            d = reduce_mod(d, phi_n);
        }
        return d;
    }
}


// Find the greatest common denomiator
// CREDIT TO ZACH FRIGGSTAD *FROM SLIDES*
uint32_t gcd_euclid_fast(uint32_t a, uint32_t b) {
  while (b > 0) {
    a %= b;

    // now swap them
    uint32_t tmp = a;
    a = b;
    b = tmp;
  }
  return a; // b is 0
}


// Random number generator
uint32_t num_gen(uint32_t bits) {
    uint32_t val, random_num = 0;
    // Loop to read from A1, to generate bit and multiply by pow(2,  bit position)
    for (int i = 0; i < bits; ++i) {
        val = analogRead(A1);
        if (val&1) {
          random_num += pow(2, i);
        }
        delay(5);
    }
    random_num += pow(2, bits);
    return random_num;
}


// Generate prime number
// FIRST NUMBER IS 14BITS AND SECOND IS 15BITS*
uint32_t prime_gen(uint32_t bits) {
    uint32_t p;
    do {
        p = num_gen(bits);
    } while(!primality(p));
    return p;
}


// Generate public key
uint32_t generate_e(uint32_t phi_n) {
    uint32_t e;
    do {
        e = num_gen(14);
    } while(gcd_euclid_fast(e, phi_n) != 1);
    return e;
}


void handshakeServer(uint32_t& serverPrivateKey, uint32_t& smod, uint32_t& ckey, uint32_t& cmod) {

	// Initializing all variables
    uint32_t serverPublicKey, serverModulus;
    generate_keys(serverPrivateKey, serverPublicKey, serverModulus);

    serverState state = LISTEN;
      
    uint32_t skey;
    skey = serverPublicKey;
    smod = serverModulus;

    // Finite state machine process for the server, conditions are found of the assignment PDF.
    while (state != S_DATA_EXCHANGE) {
        if (state == LISTEN) {
            if (Serial3.available() >= 1 && Serial3.read() == 'C') {
                state = WAITING_FOR_KEY;
            }
        }
        else if (state == WAITING_FOR_KEY) {
            if (wait_on_serial3(8, 1000)) {
                ckey = uint32_from_serial3();
                cmod = uint32_from_serial3();
                
                Serial3.write('A');
                uint32_to_serial3(skey);
                uint32_to_serial3(smod);
              
                state = WAIT_FOR_ACK;
            }
            else {
                state = LISTEN;
            }
        }
        else if (state == WAIT_FOR_ACK) {
            if (wait_on_serial3(1, 1000)) {
                if (Serial3.read() == 'A') {
                    state = S_DATA_EXCHANGE;
                }
                else if (Serial3.read() == 'C') {
                    state = WAITING_FOR_KEY;
                }
            }
            else {
                state = LISTEN;
            }
        }
    }
    return;
}


void handshakeClient(uint32_t& clientPrivateKey, uint32_t& cmod, uint32_t& skey, uint32_t& smod) {
	//Initialzing all variables.
    uint32_t clientPublicKey, clientModulus;
    generate_keys(clientPrivateKey, clientPublicKey, clientModulus);

    clientState state = START;

    uint32_t ckey;
    ckey = clientPublicKey;
    cmod = clientModulus;

    // Finite state machine process for the client, conditions are found of the assignment PDF.
    while (state != C_DATA_EXCHANGE) {
        if (state == START) {
            Serial3.write('C');
            uint32_to_serial3(ckey);
            uint32_to_serial3(cmod);
            state = WAITING_FOR_ACK;
        }
        else if (state == WAITING_FOR_ACK) {
            if (wait_on_serial3(9, 1000)) {
                if (Serial3.read() == 'A') {
                    skey = uint32_from_serial3();
                    smod = uint32_from_serial3();
                  
                    Serial3.write('A');
                    state = C_DATA_EXCHANGE;
                }
                else {
                    state = START;
                }
            }
        }
    }
    return;
}


/** Waits for a certain number of bytes on Serial3 or timeout
 * @param nbytes: the number of bytes we want
 * @param timeout: timeout period (ms); specifying a negative number
 *                 turns off timeouts (the function waits indefinitely
 *                 iF timeouts are turned off).
 * @return True if the required number of bytes have arrived.
 */
bool wait_on_serial3(uint8_t nbytes, long timeout) {
    unsigned long deadline = millis() + timeout; // wraparound not a problem
    while (Serial3.available()<nbytes && (timeout<0 ||  millis()<deadline)){
        delay (1); // be nice, no busy  loop
    }
    return Serial3.available()>=nbytes;


}

// Generate both keys and modulus, passing by reference
void generate_keys(uint32_t& e, uint32_t& d, uint32_t& n) {
    uint32_t p = prime_gen(14);
    uint32_t q = prime_gen(15);
    uint32_t phi_n = (p - 1)*(q - 1);
  
    e = generate_e(phi_n);
    d = generate_d(e, phi_n);
    n = p*q;
}

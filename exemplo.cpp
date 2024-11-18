#include <iostream>
#include <iomanip>
#include "localStorage.h"

int main()
{
	if (localStorage::get("user") == "") {
		std::string user;
		std::cout << "Digite seu usuario:";
		std::cin >> user;

		localStorage::save("user", localStorage::crypt::enc(user, "0xC0FFE"));
		localStorage::swap(localStorage::appData_()); // salva no .exe
	}
	else {
		std::cout << "ola," << localStorage::crypt::dec(localStorage::get("user"), "0xC0FFE") << "\n";
	}
}

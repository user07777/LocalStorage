#include <iostream>
#include <iomanip>
#include "localStorage.h"

int main()
{
	auto L = std::make_shared<localStorage>();
	if (L.get()->get() == "") {
		std::string user;
		std::cout << "Digite seu usuario:";
		std::cin >> user;

		L->save("user", L->enc(user, "0xC0FFE")); //salva na memoria
		L->save("pwd",  L->enc("senha", "0xC0FFE"));//salva na memoria

		L->saveExe();
		L->swap(); // salva no .exe
	}
	else {
		std::string pwd;
		std::cout << "Ola," << L->dec(L->get("user"),"0xC0FFE") << " digite sua senha\n";
		std::cin >> pwd;
		if (L->dec(L->get("pwd"), "0xC0FFE") == pwd)
			std::cout << "logado";
	}
}

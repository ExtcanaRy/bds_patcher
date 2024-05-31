#include <iostream>
#include <dirent.h>
#include <dlfcn.h>
#include <LIEF/LIEF.hpp>

#define PLUGIN_DIR "mods/"

std::vector<std::string> plugin_lst;
std::vector<void *> plugin_handle_lst;

std::vector<std::string> sym_lst;

int main(int argc, char **argv)
{
	DIR *mods_dir = opendir(PLUGIN_DIR);
	if (!mods_dir) {
		std::cout << "mods folder not found!" << std::endl;

		return -1;
	}

	dirent *ent;
	while ((ent = readdir(mods_dir))) {
		if (ent->d_name[0] == '.')
			continue;
		plugin_lst.push_back(std::string(PLUGIN_DIR) + std::string(ent->d_name));
	}

    if (!plugin_lst.size()) {
        std::cout << "no plugin found" << std::endl;

        return -1;
    }

	for (std::string str : plugin_lst) {
		void *ret = dlopen(str.c_str(), RTLD_NOW);
		if (!ret) {
			std::cout << "dlopen failed: " << str << std::endl;
			continue;
		}
		plugin_handle_lst.push_back(ret);
	}

    // call plugin "const char **reg_sym(int *)"
	for (void *handle : plugin_handle_lst) {
		void *ret = dlsym(handle, "_Z7reg_symPi");
		if (!ret) {
			std::cout << "dlsym failed! @ " << handle << std::endl;

			continue;
		}

		int num;
		const char **plugin_sym_lst = ((const char **(*)(int *))ret)(&num);

		for (int i = 0; i < num; i++) {
			for (std::string str : sym_lst) {
				if (str == plugin_sym_lst[i]) {
                    // if found same symbol in list
					goto next_loop; // continue;
				}
			}

			sym_lst.push_back(plugin_sym_lst[i]);

next_loop:
			continue;
		}
	}

	// for (std::string str : sym_lst) {
	// 	std::cout << "sym: " << str << std::endl;
	// }

    if (!sym_lst.size()) {
        std::cout << "no symbol found" << std::endl;
    }

    auto binary = LIEF::ELF::Parser::parse("bedrock_server_symbols.debug");
    if (!binary) {
        std::cout << "failed to open ELF file" << std::endl;

        return -1;
    }

	std::cout << "Processing symbols..." << std::endl;
	for (auto sym : binary->symbols()) {
		if (!sym.is_exported() && !sym.is_imported()) {
			for (auto str : sym_lst) {
				if (str == sym.name()) {
					std::cout << sym.name() << std::endl;
					binary->add_dynamic_symbol(sym);
					binary->export_symbol(sym);
				}
			}
		}
	}

	std::cout << "Writing file..." << std::endl;
	binary->write("bedrock_server_symbols_patched.debug");

	std::cout << "Finished!" << std::endl;

	return 0;
}

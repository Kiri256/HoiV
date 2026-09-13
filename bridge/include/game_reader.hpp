#pragma once

namespace hoiv {

void game_reader_bind(void* shared_block);
bool game_reader_install();
void game_reader_uninstall();
void game_reader_clear();
bool game_reader_is_armed();

}  // namespace hoiv

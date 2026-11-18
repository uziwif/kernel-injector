#include <windows.h>
#include <intrin.h>
#include <pplwin.h>
#include <vector>

#include <dependencies/vector/vector.hxx>
#include <dependencies/skcrypt/skcrypter.h>

#include <dependencies/impl/std/std.hxx>
#include <dependencies/impl/crt/crt.hxx>
#include <dependencies/impl/pe/pe.hxx>
#include <dependencies/impl/vmt/vmt.hxx>

#include <workspace/ipc/ipc.hxx>
#include <workspace/reflective/reflective.hxx>

template<typename T, typename... Args>
std::unique_ptr<T> make_unique( Args&&... args ) {
    return std::unique_ptr<T>( new T( std::forward<Args>( args )... ) );
}

#include <workspace/game/unreal/unreal.h>
#include <workspace/game/drawing/drawing.h>
#include <workspace/game/features/features.h>
#include <workspace/game/features/players/players.hxx>
#include <workspace/game/features/exploits/exploits.hxx>
#include <workspace/game/features/targeting/targeting.hxx>
#include <workspace/game/features/environment/environment.hxx>
#include <workspace/game/hooks/draw_transation.hxx>
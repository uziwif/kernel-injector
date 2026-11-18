#include <workspace/game/drawing/framework/internal/internal.h>
namespace renderer {
	internal::c_draw_data g_draw_data{ };
}

#include <workspace/game/drawing/framework/renderer/renderer.hxx>
#include <workspace/game/drawing/framework/framework.hxx>

namespace drawing {
	framework::c_framework g_framework { };
}

#include <workspace/game/drawing/elements/visuals/visuals.hxx>
#include <workspace/game/drawing/elements/widgets/widgets.h>
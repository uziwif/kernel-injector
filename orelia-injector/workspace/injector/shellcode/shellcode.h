#pragma once

namespace shellcode {
    using namespace asmjit;
    using namespace asmjit::x86;

#pragma pack(push, 8) 
    struct inject_data_t {
        volatile std::uint32_t m_status;
        std::uint64_t m_return;
        /* Range of graphics-hook64 in the target. The shellcode only runs the
         * payload when the return address belongs to that module, i.e. when
         * the slot was called by the OBS present shim and not by whatever
         * else a probed candidate slot turned out to be. */
        std::uint64_t m_hook_base;
        std::uint64_t m_hook_size;
        std::uint64_t m_last_caller;
    };
#pragma pack(pop)
}


namespace reflective {
    enum e_reflective_status : std::uint32_t {
        invalid_parameters = 1,
        mapping_failed = 2,
        dllmain_failed = 3,
        executed_dll_main = 4
    };

    struct reflective_data_t {
        std::uint64_t m_base_address;
        std::uint32_t m_dll_return;
        std::uint64_t m_dll_base;
        std::size_t m_dll_size;
    };
}
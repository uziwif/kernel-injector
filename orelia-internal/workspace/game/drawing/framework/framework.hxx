namespace framework {
    class c_framework {
    public:
        bool render( sdk::u_canvas* canvas ) {
            if ( !renderer::g_draw_data.is_valid( ) ) {
                return false;
            }

            if ( !m_background.empty( ) ) {
                for ( auto i = 0; i < m_background.size( ); i++ ) {
                    auto& element = m_background[ i ];
                    draw( canvas, element );
                }
                m_background.clear( );
            }

            if ( !m_foreground.empty( ) ) {
                for ( auto i = 0; i < m_foreground.size( ); i++ ) {
                    auto& element = m_foreground[ i ];
                    draw( canvas, element );
                }
                m_foreground.clear( );
            }

            return true;
        }

        bool update( sdk::u_canvas* canvas ) {
            renderer::g_draw_data.set_canvas( canvas );
            renderer::g_draw_data.set_font( sdk::font::g_default_font );
            return renderer::g_draw_data.is_valid( );
        }

        void reserve( size_t render_count ) {
            m_background.resize( render_count );
            m_foreground.resize( render_count );
        }

        void add_line( const sdk::fvector2d& start, const sdk::fvector2d& end,
            const sdk::flinear_color& color, float thickness = 1.0f, bool foreground = true ) {
            internal::s_draw_info info{};
            info.draw_type = internal::e_draw_type::line;
            info.position_a = start;
            info.position_b = end;
            info.color = color;
            info.thickness = thickness;

            add_element( info, foreground );
        }

        void add_rectangle( const sdk::fvector2d& min, const sdk::fvector2d& max,
            const sdk::flinear_color& color, float thickness = 1.0f, bool foreground = true ) {
            internal::s_draw_info info{};
            info.draw_type = internal::e_draw_type::rectangle;
            info.position_a = min;
            info.position_b = max;
            info.color = color;
            info.thickness = thickness;

            add_element( info, foreground );
        }

        void add_filled_rectangle( const sdk::fvector2d& min, const sdk::fvector2d& max,
            const sdk::flinear_color& color, bool foreground = true ) {
            internal::s_draw_info info{};
            info.draw_type = internal::e_draw_type::rect_filled;
            info.position_a = min;
            info.position_b = max;
            info.color = color;

            add_element( info, foreground );
        }

        void add_gradient_rectangle( const sdk::fvector2d& min, const sdk::fvector2d& max,
            const sdk::flinear_color& color1, const sdk::flinear_color& color2,
            bool foreground = true ) {
            internal::s_draw_info info{};
            info.draw_type = internal::e_draw_type::gradient_rect;
            info.position_a = min;
            info.position_b = max;
            info.color = color1;
            info.secondary_color = color2;

            add_element( info, foreground );
        }

        void add_circle( const sdk::fvector2d& center, double radius,
            const sdk::flinear_color& color, float thickness = 1.0f,
            double segments = 32.0, bool foreground = true ) {
            internal::s_draw_info info{};
            info.draw_type = internal::e_draw_type::circle;
            info.position_a = center;
            info.radius = radius;
            info.color = color;
            info.thickness = thickness;
            info.segments = segments;

            add_element( info, foreground );
        }

        void add_text( const sdk::fvector2d& position, const sdk::fstring& content,
            const sdk::flinear_color& color, double size = 12.0,
            bool centered_x = false, bool centered_y = false, bool foreground = true ) {
            internal::s_draw_info info{};
            info.draw_type = internal::e_draw_type::text;
            info.position_a = position;
            info.content = content;
            info.color = color;
            info.size = size;
            info.centered_x = centered_x;
            info.centered_y = centered_y;

            add_element( info, foreground );
        }

        void add_rounded_rectangle( const sdk::fvector2d& min, const sdk::fvector2d& max,
            double radius, const sdk::flinear_color& color,
            float thickness = 1.0f, bool filled = false, bool foreground = true ) {
            internal::s_draw_info info{};
            info.draw_type = internal::e_draw_type::rounded_rect;
            info.position_a = min;
            info.position_b = max;
            info.color = color;
            info.thickness = thickness;
            info.radius = radius;
            info.filled = filled;

            add_element( info, foreground );
        }

        void add_diamond( const sdk::fvector2d& center, double size,
            const sdk::flinear_color& color, float thickness = 1.0f, bool foreground = true ) {
            internal::s_draw_info info{};
            info.draw_type = internal::e_draw_type::diamond;
            info.position_a = center;
            info.size = size;
            info.color = color;
            info.thickness = thickness;

            add_element( info, foreground );
        }

    private:
        internal::c_draw_data* m_draw_data = nullptr;
        std::vector<internal::s_draw_info> m_background;
        std::vector<internal::s_draw_info> m_foreground;

        void add_element( internal::s_draw_info draw_info, bool foreground = true ) {
            auto& target = foreground ? m_foreground : m_background;
            target.emplace_back( draw_info );
        }

        void draw( sdk::u_canvas* canvas, internal::s_draw_info& info ) {
            switch ( info.draw_type ) {
            case internal::e_draw_type::line: {
                canvas->k2_draw_line(
                    sdk::fvector2d( 1.0, 1.0 ),
                    sdk::fvector2d( 200, 200 ),
                    100.f,
                    sdk::flinear_color( 1.0, 0.0, 0.0, 1.0 )
                );

                //canvas->k2_draw_line( info.position_a, info.position_b, info.thickness, info.color );
            } break;

            //case internal::e_draw_type::rectangle: {
            //    renderer::draw_rect( canvas, info.position_a, info.position_b - info.position_a, info.color, info.thickness );
            //} break;

            //case internal::e_draw_type::rect_filled: {
            //    renderer::draw_rect_filled( canvas, info.position_a, info.position_b - info.position_a, info.color, 1.0f );
            //} break;

            //case internal::e_draw_type::gradient_rect: {
            //    renderer::draw_gradient_rect( canvas, info.position_a, info.position_b - info.position_a,
            //        info.color, info.secondary_color, 1.0f );
            //} break;

            //case internal::e_draw_type::circle: {
            //    renderer::draw_circle( canvas, info.position_a, info.color, info.radius,
            //        info.segments, info.thickness, info.filled );
            //} break;

            //case internal::e_draw_type::text: {
            //    if ( renderer::g_draw_data.get_font( ) ) {
            //        canvas->k2_draw_text( renderer::g_draw_data.get_font( ), info.content,
            //            info.position_a, sdk::fvector2d( info.size, info.size ), info.color,
            //            info.centered_x, info.centered_y, info.outlined );
            //    }
            //} break;

            //case internal::e_draw_type::diamond: {
            //    renderer::draw_diamond( canvas, info.position_a, sdk::fvector2d( info.size, info.size ), info.color );
            //} break;

            //case internal::e_draw_type::rounded_rect: {
            //    renderer::draw_rounded_rect( canvas, info.position_a, info.position_b - info.position_a,
            //        info.color, info.radius, info.filled );
            //} break;
            }
        }
    };
}
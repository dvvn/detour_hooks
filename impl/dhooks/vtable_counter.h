#pragma once

#if 0

//this fuck resharper and doesnt work

//#include "core.h"
namespace minhook{
    struct vtable_counter
    {
#define GET(x) virtual size_t get##x() const { return x; }
#define GET10(x) GET(x##0) GET(x##1) GET(x##2) GET(x##3) GET(x##4) GET(x##5) GET(x##6) GET(x##7) GET(x##8) GET(x##9)
#define GET100(x) GET10(x##0) GET10(x##1) GET10(x##2) GET10(x##3) GET10(x##4) GET10(x##5) GET10(x##6) GET10(x##7) GET10(x##8) GET10(x##9)

#pragma region get_macro
        GET10( )
        GET10(1)
        GET10(2)
        GET10(3)
        GET10(4)
        GET10(5)
        GET10(6)
        GET10(7)
        GET10(8)
        GET10(9)
        GET100(1)
        GET100(2)
        GET100(3)
        GET100(4)
        GET100(5)
        GET100(6)
        GET100(7)
        GET100(8)
        GET100(9)
#pragma endregion

#undef GET
#undef GET10
#undef GET100
    };

    template <typename T, typename Fn>
    size_t GetVFuncIndex(Fn func)
    {
        vtable_counter vt;
        T*             t = reinterpret_cast<T*>(&vt);

        using GetIndex_t = size_t(T::*)( );
        GetIndex_t get_index = (GetIndex_t)func;
        return (t->*get_index)( );
    }

}

#endif
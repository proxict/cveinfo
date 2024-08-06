include(FetchContent)
FetchContent_Declare(cpr
    GIT_REPOSITORY https://github.com/libcpr/cpr.git
    GIT_TAG        1.10.5
    EXCLUDE_FROM_ALL
)

set(BUILD_CPR_TESTS OFF CACHE BOOL "Don't build CPR tests" FORCE) # old cpr
set(CPR_BUILD_TESTS OFF CACHE BOOL "Don't build CPR tests" FORCE) # newer cpr
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Don't build CPR as a shared library" FORCE)
FetchContent_MakeAvailable(cpr)

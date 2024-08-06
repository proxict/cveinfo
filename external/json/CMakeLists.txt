set(JSON_BuildTests OFF CACHE INTERNAL "")
include(FetchContent)
FetchContent_Declare(json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(json)

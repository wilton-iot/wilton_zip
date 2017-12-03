/* 
 * File:   wiltoncall_zip.cpp
 * Author: alex
 *
 * Created on December 3, 2017, 7:17 PM
 */

#include "staticlib/support.hpp"

#include "wilton/support/buffer.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/registrar.hpp"

extern "C" char* wilton_module_init() {
    try {
        // register calls
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

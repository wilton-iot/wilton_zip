/*
 * Copyright 2017, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * File:   wiltoncall_zip.cpp
 * Author: alex
 *
 * Created on December 3, 2017, 7:17 PM
 */

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "utf8.h"

#include "staticlib/compress.hpp"
#include "staticlib/json.hpp"
#include "staticlib/support.hpp"
#include "staticlib/tinydir.hpp"
#include "staticlib/unzip.hpp"
#include "staticlib/utils.hpp"

#include "wilton/support/buffer.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/logging.hpp"
#include "wilton/support/registrar.hpp"
#include "wilton/support/tl_registry.hpp"

namespace wilton {
namespace zip {

namespace { //anonymous

const std::string logger = std::string("wilton.zip");

std::vector<std::string> extract_entry_names(const std::vector<sl::json::value>& enames) {
    if (0 == enames.size()) {
        throw support::exception(TRACEMSG("Invalid empty list of entries specified"));
    }
    auto res = std::vector<std::string>();
    res.reserve(enames.size());
    for (auto& el : enames) {
        const std::string& name = el.as_string_nonempty_or_throw("entries");
        res.emplace_back(std::string(name.data(), name.length()));
    }
    return res;
}

class zip_file_writer {
    std::unique_ptr<sl::compress::zip_sink<sl::tinydir::file_sink>> sink;
    std::vector<std::string> entry_names;
    bool hex;
    bool fs_paths;
    size_t idx = 0;

public:
    zip_file_writer(const std::string& path, const std::vector<sl::json::value>& enames,
            bool hex_format, bool use_fs_paths) :
    sink(new sl::compress::zip_sink<sl::tinydir::file_sink>(sl::tinydir::file_sink(path))),
    entry_names(extract_entry_names(enames)),
    hex(hex_format),
    fs_paths(use_fs_paths) { }

    zip_file_writer(const zip_file_writer&) = delete;

    zip_file_writer& operator=(const zip_file_writer&) = delete;

    zip_file_writer(zip_file_writer&& other) :
    sink(std::move(other.sink)),
    entry_names(std::move(other.entry_names)),
    hex(other.hex),
    fs_paths(other.fs_paths),
    idx(other.idx) {
        other.hex = false;
        other.fs_paths = false;
        other.idx = 0;
    }

    zip_file_writer& operator=(zip_file_writer&& other) = delete;

    const std::string& next_entry_name() {
        if (idx >= entry_names.size()) {
            throw support::exception(TRACEMSG("Entries number threshold exceeded," +
                    " idx: [" + sl::support::to_string(idx) + "]"));
        }
        auto& res = entry_names.at(this->idx);
        this->idx = this->idx + 1;
        return res;
    }

    sl::compress::zip_sink<sl::tinydir::file_sink>& get_sink() {
        return *sink.get();
    }

    bool is_hex() {
        return hex;
    }

    bool use_fs_paths() {
        return fs_paths;
    }
};

// initialized from wilton_module_init
std::shared_ptr<support::tl_registry<zip_file_writer>> local_registry() {
    static auto registry = std::make_shared<support::tl_registry<zip_file_writer>>();
    return registry;
}

} // namespace

support::buffer read_file(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rpath = std::ref(sl::utils::empty_string());
    auto hex = false;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("path" == name) {
            rpath = fi.as_string_nonempty_or_throw(name);
        } else if ("hex" == name) {
            hex = fi.as_bool_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (rpath.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'path' not specified"));
    const std::string& path = rpath.get();
    // read file
    auto idx = sl::unzip::file_index(path);
    auto res = std::vector<sl::json::field>();
    for (auto& en : idx.get_entries()) {
        auto stream = sl::unzip::open_zip_entry(idx, en);
        auto src = sl::io::streambuf_source(stream->rdbuf());
        auto fi = sl::json::field();
        if (!hex) {
            auto sink = sl::io::string_sink();
            sl::io::copy_all(src, sink);
            auto& str_raw = sink.get_string();
            if (utf8::is_valid(str_raw.begin(), str_raw.end())) {
                fi = sl::json::field(en, std::move(str_raw));
            } else {
                auto str_utf8 = std::string();
                utf8::replace_invalid(str_raw.begin(), str_raw.end(), std::back_inserter(str_utf8));
                fi = sl::json::field(en, std::move(str_utf8));
            }
        } else {
            auto sink = sl::io::string_sink();
            {
                auto hexer = sl::io::make_hex_sink(sink);
                sl::io::copy_all(src, hexer);
            }
            fi = sl::json::field(en, std::move(sink.get_string()));
        }
        res.emplace_back(std::move(fi));
    }
    return support::make_json_buffer(std::move(res));
}

support::buffer read_file_entry(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rpath = std::ref(sl::utils::empty_string());
    auto rentry = std::ref(sl::utils::empty_string());
    auto hex = false;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("path" == name) {
            rpath = fi.as_string_nonempty_or_throw(name);
        } else if ("entry" == name) {
            rentry = fi.as_string_nonempty_or_throw(name);
        } else if ("hex" == name) {
            hex = fi.as_bool_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (rpath.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'path' not specified"));
    if (rentry.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'entry' not specified"));
    const std::string& path = rpath.get();
    const std::string& entry = rentry.get();
    // read file
    auto idx = sl::unzip::file_index(path);
    sl::unzip::file_entry en = idx.find_zip_entry(entry);
    if (en.is_empty()) throw support::exception(TRACEMSG(
            "Invalid ZIP entry specified: [" + entry + "], file: [" + path + "]"));
    auto stream = sl::unzip::open_zip_entry(idx, entry);
    auto src = sl::io::streambuf_source(stream->rdbuf());
    if (!hex) {
        auto buf = support::make_source_buffer(src);
        if (utf8::is_valid(buf.begin(), buf.end())) {
            return buf;
        } else {
            auto deferred = sl::support::defer([buf]() STATICLIB_NOEXCEPT {
                wilton_free(buf.data());
            });
            auto str_utf8 = std::string();
            utf8::replace_invalid(buf.begin(), buf.end(), std::back_inserter(str_utf8));
            return support::make_string_buffer(str_utf8);
        }
    } else {
        return support::make_hex_buffer(src);
    }
}

support::buffer unzip_file_entries(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rpath = std::ref(sl::utils::empty_string());
    auto rroot = std::ref(sl::utils::empty_string());
    // std::ref doesn't work here
    auto pentries = sl::support::observer_ptr<const std::vector<sl::json::field>>();
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("path" == name) {
            rpath = fi.as_string_nonempty_or_throw(name);
        } else if ("destRoot" == name) {
            rroot = fi.as_string_nonempty_or_throw(name);
        } else if ("entries" == name) {
            pentries.reset(std::addressof(fi.as_object_or_throw(name)));
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (rpath.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'path' not specified"));
    if (!pentries.has_value()) throw support::exception(TRACEMSG(
            "Required parameter 'entries' not specified"));
    if (0 == pentries->size()) throw support::exception(TRACEMSG(
            "Required parameter 'entries' is empty"));
    for (auto& en : *pentries.get()) {
        if (sl::json::type::string != en.json_type()) {
            throw support::exception(TRACEMSG("Invalid entry specified," +
                    " name: [" + en.name() + "]," +
                    " must contain 'src_path_in_zip' -> 'dest_path_in_fs' mapping"));
        }
    }
    const std::string& path = rpath.get();
    const std::string& root = rroot.get();
    const std::vector<sl::json::field>& entries = *pentries.get();
    // read file
    auto idx = sl::unzip::file_index(path);
    // create dest root dir if specified
    if (!root.empty()) {
        sl::tinydir::create_directory(root);
    }
    // unzip entries to files
    for (auto& en : entries) {
        auto& name = en.name();
        auto& path = en.as_string_or_throw(name);
        if (!(name.length() > 0 && '/' == name.back())) {
            auto stream = sl::unzip::open_zip_entry(idx, name);
            auto src = sl::io::streambuf_source(stream->rdbuf());
            auto file = sl::tinydir::file_sink(path);
            auto dest = sl::io::make_buffered_sink(file);
            sl::io::copy_all(src, dest);
        } else {
            sl::tinydir::create_directory(path);
        }
    }
    return support::make_null_buffer();
}

support::buffer list_file_entries(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rpath = std::ref(sl::utils::empty_string());
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("path" == name) {
            rpath = fi.as_string_nonempty_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (rpath.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'path' not specified"));
    const std::string& path = rpath.get();
    // read file
    auto idx = sl::unzip::file_index(path);
    auto res = std::vector<sl::json::value>();
    for (auto& en : idx.get_entries()) {
        res.push_back(en);
    }
    return support::make_json_buffer(std::move(res));
}

support::buffer open_tl_file_writer(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rpath = std::ref(sl::utils::empty_string());
    auto rentries = std::ref(sl::json::null_value_ref());
    auto hex = false;
    auto fs_paths = false;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("path" == name) {
            rpath = fi.as_string_nonempty_or_throw(name);
        } else if ("entries" == name) {
            rentries = fi.val();
        } else if ("hex" == name) {
            hex = fi.as_bool_or_throw(name);
        } else if ("fsPaths" == name) {
            fs_paths = fi.as_bool_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (rpath.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'path' not specified"));
    if (sl::json::type::nullt == rentries.get().json_type()) throw support::exception(TRACEMSG(
            "Required parameter 'entries' not specified"));
    if (sl::json::type::array != rentries.get().json_type()) throw support::exception(TRACEMSG(
            "Parameter 'entries' must be an 'array'," +
            " specified type: [" + sl::json::stringify_json_type(rentries.get().json_type()) + "]"));
    const std::string& path = rpath.get();
    const std::vector<sl::json::value>& entries = rentries.get().as_array();
    // create writer
    auto reg = local_registry();
    auto writer = zip_file_writer(path, entries, hex, fs_paths);
    reg->put(std::move(writer));
    wilton::support::log_debug(logger, std::string("TL ZIP file writer opened,") + 
            " path: [" + path + "], entries: [" + json["entries"].dumps() + "]");
    return support::make_null_buffer();
}

support::buffer write_tl_entry_content(sl::io::span<const char> data) {
    auto reg = local_registry();
    auto& writer = reg->peek();
    auto& sink = writer.get_sink();
    auto& name = writer.next_entry_name();
    wilton::support::log_debug(logger, std::string("Writing TL ZIP entry,") + 
            " name: [" + name + "]");
    sink.add_entry(name);
    size_t written = 0;
    if (writer.is_hex()) {
        auto src = sl::io::array_source(data.data(), data.size());
        auto unhexer = sl::io::make_hex_source(src);
        written = sl::io::copy_all(unhexer, sink);
    } else if (writer.use_fs_paths()) {
        // write file contents skipping dir entries
        if (!(name.length() > 0 && '/' == name.back())) {
            auto path = std::string(data.data(), data.size());
            auto src = sl::tinydir::file_source(path);
            written = sl::io::copy_all(src, sink);
        }
    } else {
        auto src = sl::io::array_source(data.data(), data.size());
        written = sl::io::copy_all(src, sink);
    }
    wilton::support::log_debug(logger, std::string("TL ZIP entry written,") + 
            " bytes: [" + sl::support::to_string(written) + "]");
    return support::make_null_buffer();
}

support::buffer close_tl_file_writer(sl::io::span<const char>) {
    auto reg = local_registry();
    {
        // will be destroyed at the end of scope
        // no reinsertion logic on unlikely error
        auto writer = reg->remove();
    }
    wilton::support::log_debug(logger, std::string("TL ZIP file writer closed,"));
    return support::make_null_buffer();
}

} // namespace
}

extern "C" char* wilton_module_init() {
    try {
        wilton::zip::local_registry();
        wilton::support::register_wiltoncall("zip_read_file", wilton::zip::read_file);
        wilton::support::register_wiltoncall("zip_read_file_entry", wilton::zip::read_file_entry);
        wilton::support::register_wiltoncall("zip_unzip_file_entries", wilton::zip::unzip_file_entries);
        wilton::support::register_wiltoncall("zip_list_file_entries", wilton::zip::list_file_entries);
        wilton::support::register_wiltoncall("zip_open_tl_file_writer", wilton::zip::open_tl_file_writer);
        wilton::support::register_wiltoncall("zip_write_tl_entry_content", wilton::zip::write_tl_entry_content);
        wilton::support::register_wiltoncall("zip_close_tl_file_writer", wilton::zip::close_tl_file_writer);
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

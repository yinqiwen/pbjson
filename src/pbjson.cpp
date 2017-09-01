/*
 *Copyright (c) 2013-2014, yinqiwen <yinqiwen@gmail.com>
 *All rights reserved.
 *
 *Redistribution and use in source and binary forms, with or without
 *modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of Redis nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 *BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 *THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "pbjson.hpp"
#include "bin2ascii.h"
#include "rapidjson/rapidjson.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#define RETURN_ERR(ID, CAUSE) \
    do                        \
    {                         \
        err = CAUSE;          \
        return ID;            \
    } while (0)

#define UNEXPECTED_FIELD_TYPE_MSG(field, TYPE) \
    (std::string() + "Field `" + field->name() + "` is expecting an `" #TYPE "` value")
#define UNEXPECTED_MSG(field, MSG) (std::string() + "Field `" + field->name() + "` is unexpected: " MSG)
using namespace google::protobuf;
namespace pbjson
{
static rapidjson::Value* parse_msg(const Message* msg, rapidjson::Value::AllocatorType& allocator);
static rapidjson::Value* field2json(const Message* msg,
                                    const FieldDescriptor* field,
                                    rapidjson::Value::AllocatorType& allocator)
{
    const Reflection* ref = msg->GetReflection();
    const bool repeated   = field->is_repeated();

    size_t array_size = 0;
    if (repeated)
    {
        array_size = ref->FieldSize(*msg, field);
    }
    rapidjson::Value* json = NULL;
    if (repeated)
    {
        json = new rapidjson::Value(rapidjson::kArrayType);
    }
    switch (field->cpp_type())
    {
#define HANDLE_2JSON_FIELD(PB_TYPE, TYPE)                                   \
    case FieldDescriptor::CPPTYPE_##PB_TYPE:                                \
        if (repeated)                                                       \
        {                                                                   \
            for (size_t i = 0; i != array_size; ++i)                        \
            {                                                               \
                rapidjson::Value v(ref->GetRepeated##TYPE(*msg, field, i)); \
                json->PushBack(v, allocator);                               \
            }                                                               \
        }                                                                   \
        else                                                                \
        {                                                                   \
            json = new rapidjson::Value(ref->Get##TYPE(*msg, field));       \
        }                                                                   \
        break;

        HANDLE_2JSON_FIELD(DOUBLE, Double)
        HANDLE_2JSON_FIELD(FLOAT, Float)

        HANDLE_2JSON_FIELD(INT64, Int64)
        HANDLE_2JSON_FIELD(UINT64, UInt64)

        HANDLE_2JSON_FIELD(INT32, Int32)
        HANDLE_2JSON_FIELD(UINT32, UInt32)

        HANDLE_2JSON_FIELD(BOOL, Bool)
        case FieldDescriptor::CPPTYPE_STRING:
        {
            const bool is_binary = field->type() == FieldDescriptor::TYPE_BYTES;
            if (repeated)
            {
                for (size_t i = 0; i != array_size; ++i)
                {
                    std::string value = ref->GetRepeatedString(*msg, field, i);
                    if (is_binary)
                    {
                        value = b64_encode(value);
                    }
                    rapidjson::Value v(value.data(), static_cast<rapidjson::SizeType>(value.size()), allocator);
                    json->PushBack(v, allocator);
                }
            }
            else
            {
                std::string value = ref->GetString(*msg, field);
                if (is_binary)
                {
                    value = b64_encode(value);
                }
                json = new rapidjson::Value(value.data(), value.size(), allocator);
            }
            break;
        }
        case FieldDescriptor::CPPTYPE_MESSAGE:
            if (repeated)
            {
                for (size_t i = 0; i != array_size; ++i)
                {
                    const Message* value = &(ref->GetRepeatedMessage(*msg, field, i));
                    rapidjson::Value* v  = parse_msg(value, allocator);
                    json->PushBack(*v, allocator);
                    delete v;
                }
            }
            else
            {
                const Message* value = &(ref->GetMessage(*msg, field));
                json                 = parse_msg(value, allocator);
            }
            break;
        case FieldDescriptor::CPPTYPE_ENUM:
            if (repeated)
            {
                for (size_t i = 0; i != array_size; ++i)
                {
                    const EnumValueDescriptor* value = ref->GetRepeatedEnum(*msg, field, i);
                    rapidjson::Value v(value->number());
                    json->PushBack(v, allocator);
                }
            }
            else
            {
                json = new rapidjson::Value(ref->GetEnum(*msg, field)->number());
            }
            break;
        default:
            break;
    }
    return json;
}

static rapidjson::Value* parse_msg(const Message* msg, rapidjson::Value::AllocatorType& allocator)
{
    const Descriptor* d = msg->GetDescriptor();
    if (!d) return NULL;
    size_t count           = d->field_count();
    rapidjson::Value* root = new rapidjson::Value(rapidjson::kObjectType);
    if (!root) return NULL;
    for (size_t i = 0; i != count; ++i)
    {
        const FieldDescriptor* field = d->field(i);
        if (!field)
        {
            delete root;
            return NULL;
        }

        const Reflection* ref = msg->GetReflection();
        if (!ref)
        {
            delete root;
            return NULL;
        }
        if (field->is_optional() && !ref->HasField(*msg, field))
        {
            // do nothing
        }
        else
        {
            rapidjson::Value* field_json = field2json(msg, field, allocator);
            rapidjson::Value field_name(field->name().c_str(), field->name().size());
            root->AddMember(field_name, *field_json, allocator);
            delete field_json;
        }
    }
    return root;
}
static int parse_json(const rapidjson::Value* json, Message* msg, std::string& err);
static int json2field(const rapidjson::Value* json, Message* msg, const FieldDescriptor* field, std::string& err)
{
    const Reflection* ref = msg->GetReflection();
    const bool repeated   = field->is_repeated();
    switch (field->cpp_type())
    {
#define HANDLE_2PB_FIELD_EX(PBTYPE, TYPE, JSON_TYPE)                              \
    case FieldDescriptor::CPPTYPE_##PBTYPE:                                       \
    {                                                                             \
        if (!json->Is##JSON_TYPE())                                               \
        {                                                                         \
            RETURN_ERR(ERR_INVALID_JSON, UNEXPECTED_FIELD_TYPE_MSG(field, TYPE)); \
        }                                                                         \
        if (repeated)                                                             \
        {                                                                         \
            ref->Add##TYPE(msg, field, json->Get##JSON_TYPE());                   \
        }                                                                         \
        else                                                                      \
        {                                                                         \
            ref->Set##TYPE(msg, field, json->Get##JSON_TYPE());                   \
        }                                                                         \
        break;                                                                    \
    }
#define HANDLE_2PB_FIELD(PBTYPE, TYPE) HANDLE_2PB_FIELD_EX(PBTYPE, TYPE, TYPE)

        HANDLE_2PB_FIELD_EX(INT32, Int32, Int)
        HANDLE_2PB_FIELD_EX(UINT32, UInt32, Uint)

        HANDLE_2PB_FIELD(INT64, Int64)
        HANDLE_2PB_FIELD_EX(UINT64, UInt64, Uint64)

        HANDLE_2PB_FIELD(BOOL, Bool)

        // special for double/float
        case FieldDescriptor::CPPTYPE_DOUBLE:
        {
            if (!json->IsDouble() && !json->IsInt())
            {
                RETURN_ERR(ERR_INVALID_JSON, UNEXPECTED_FIELD_TYPE_MSG(field, Double));
            }
            if (repeated)
            {
                ref->AddDouble(msg, field, json->IsDouble() ? json->GetDouble() : json->GetInt());
            }
            else
            {
                ref->SetDouble(msg, field, json->IsDouble() ? json->GetDouble() : json->GetInt());
            }
            break;
        }
        case FieldDescriptor::CPPTYPE_FLOAT:
        {
            if (!json->IsFloat() && !json->IsInt())
            {
                RETURN_ERR(ERR_INVALID_JSON, UNEXPECTED_FIELD_TYPE_MSG(field, Float));
            }
            if (repeated)
            {
                ref->AddFloat(msg, field, json->IsFloat() ? json->GetFloat() : json->GetInt());
            }
            else
            {
                ref->SetFloat(msg, field, json->IsFloat() ? json->GetFloat() : json->GetInt());
            }
            break;
        }
        case FieldDescriptor::CPPTYPE_STRING:
        {
            if (!json->IsString())
            {
                RETURN_ERR(ERR_INVALID_JSON, UNEXPECTED_FIELD_TYPE_MSG(field, String));
            }

            const char* value = json->GetString();
            uint32_t str_size = json->GetStringLength();
            std::string str_value(value, str_size);
            if (field->type() == FieldDescriptor::TYPE_BYTES)
            {
                if (repeated)
                {
                    ref->AddString(msg, field, b64_decode(str_value));
                }
                else
                {
                    ref->SetString(msg, field, b64_decode(str_value));
                }
            }
            else
            {
                if (repeated)
                {
                    ref->AddString(msg, field, str_value);
                }
                else
                {
                    ref->SetString(msg, field, str_value);
                }
            }
            break;
        }
        case FieldDescriptor::CPPTYPE_MESSAGE:
        {
            Message* mf = (repeated) ? ref->AddMessage(msg, field) : ref->MutableMessage(msg, field);
            return parse_json(json, mf, err);
        }
        case FieldDescriptor::CPPTYPE_ENUM:
        {
            const EnumDescriptor* ed      = field->enum_type();
            const EnumValueDescriptor* ev = 0;
            if (json->GetType() == rapidjson::kNumberType)
            {
                ev = ed->FindValueByNumber(json->GetInt());
            }
            else if (json->GetType() == rapidjson::kStringType)
            {
                ev = ed->FindValueByName(json->GetString());
            }
            else
            {
                RETURN_ERR(ERR_INVALID_JSON, UNEXPECTED_FIELD_TYPE_MSG(field, IntegerOrString));
            }

            if (!ev) RETURN_ERR(ERR_INVALID_JSON, UNEXPECTED_MSG(field, "Enum value not found"));
            if (repeated)
            {
                ref->AddEnum(msg, field, ev);
            }
            else
            {
                ref->SetEnum(msg, field, ev);
            }
            break;
        }
        default:
            break;
    }
    return 0;
}

static int parse_json(const rapidjson::Value* json, Message* msg, std::string& err)
{
    if (NULL == json || json->GetType() != rapidjson::kObjectType)
    {
        return ERR_INVALID_ARG;
    }
    const Descriptor* d   = msg->GetDescriptor();
    const Reflection* ref = msg->GetReflection();
    if (!d || !ref)
    {
        RETURN_ERR(ERR_INVALID_PB, "invalid pb object");
    }
    for (rapidjson::Value::ConstMemberIterator itr = json->MemberBegin(); itr != json->MemberEnd(); ++itr)
    {
        const char* name             = itr->name.GetString();
        const FieldDescriptor* field = d->FindFieldByName(name);
        if (!field) field            = ref->FindKnownExtensionByName(name);
        if (!field) continue;  // TODO: we should not fail here, instead write this value into an unknown field
        if (itr->value.GetType() == rapidjson::kNullType)
        {
            ref->ClearField(msg, field);
            continue;
        }
        if (field->is_repeated())
        {
            if (itr->value.GetType() != rapidjson::kArrayType)
                RETURN_ERR(ERR_INVALID_JSON, UNEXPECTED_MSG(field, "Not array"));
            for (rapidjson::Value::ConstValueIterator ait = itr->value.Begin(); ait != itr->value.End(); ++ait)
            {
                int ret = json2field(ait, msg, field, err);
                if (ret != 0)
                {
                    return ret;
                }
            }
        }
        else
        {
            int ret = json2field(&(itr->value), msg, field, err);
            if (ret != 0)
            {
                return ret;
            }
        }
    }
    return 0;
}

void json2string(const rapidjson::Value* json, std::string& str)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    json->Accept(writer);
    str.append(buffer.GetString(), buffer.GetSize());
}

void pb2json(const Message* msg, std::string& str)
{
    rapidjson::Value::AllocatorType allocator;
    rapidjson::Value* json = parse_msg(msg, allocator);
    json2string(json, str);
    delete json;
}

rapidjson::Value* pb2jsonobject(const google::protobuf::Message* msg)
{
    rapidjson::Value::AllocatorType allocator;
    return parse_msg(msg, allocator);
}

rapidjson::Value* pb2jsonobject(const google::protobuf::Message* msg, rapidjson::Value::AllocatorType& allocator)
{
    return parse_msg(msg, allocator);
}

int json2pb(const std::string& json, google::protobuf::Message* msg, std::string& err)
{
    rapidjson::Document d;
    d.Parse<0>(json.c_str());
    if (d.HasParseError())
    {
        err += d.GetParseError();
        return ERR_INVALID_ARG;
    }
    int ret = jsonobject2pb(&d, msg, err);
    return ret;
}
int jsonobject2pb(const rapidjson::Value* json, google::protobuf::Message* msg, std::string& err)
{
    return parse_json(json, msg, err);
}
}

//
// Created by parallax
//

#ifndef PARALLAX_MULTIDEXCODE_H
#define PARALLAX_MULTIDEXCODE_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include "CodeItem.h"
#include "common/parallax_log.h"

namespace parallax::data {
        class MultiDexCode {
        private:
            size_t m_size{0};
            uint8_t *m_buffer{nullptr};
            const uint8_t *m_source_buffer{nullptr};
            size_t m_source_size{0};
            bool m_skip_parse{false};

            // The authenticated plaintext vault is copied into its own anonymous mapping.
            // m_owned_mapping includes inaccessible guard pages on both sides; m_owned_buffer
            // points at the usable middle pages only.
            uint8_t *m_owned_mapping{nullptr};
            size_t m_owned_mapping_size{0};
            uint8_t *m_owned_buffer{nullptr};
            size_t m_owned_buffer_size{0};
        public:
            static MultiDexCode *getInst();

            void init(uint8_t *buffer, size_t size);

            uint8_t readUInt8(uint32_t offset);

            uint16_t readUInt16(uint32_t offset);

            uint32_t readUInt32(uint32_t offset);

            uint16_t readVersion();

            uint16_t readDexCount();

            uint32_t *readDexCodeIndex(int *count);

            parallax::data::CodeItem *nextCodeItem(uint32_t *offset);
        };
    }



#endif //PARALLAX_MULTIDEXCODE_H

//
// Created by parallax
//

#ifndef PARALLAX_MULTIDEXCODE_H
#define PARALLAX_MULTIDEXCODE_H

#include <cstdint>
#include <cstring>
#include "CodeItem.h"
#include "common/parallax_log.h"

namespace parallax::data {
        class MultiDexCode {
        private:
            size_t m_size;
            uint8_t *m_buffer;
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

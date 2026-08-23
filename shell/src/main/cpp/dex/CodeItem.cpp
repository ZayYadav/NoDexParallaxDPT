//
// Created by parallax
//
#include "CodeItem.h"

uint32_t parallax::data::CodeItem::getMethodIdx() const {
    return mMethodIdx;
}

void parallax::data::CodeItem::setMethodIdx(uint32_t methodIdx) {
    CodeItem::mMethodIdx = methodIdx;
}

uint32_t parallax::data::CodeItem::getInsnsSize() const {
    return mInsnsSize;
}

void parallax::data::CodeItem::setInsnsSize(uint32_t size) {
    CodeItem::mInsnsSize = size;
}

uint8_t *parallax::data::CodeItem::getInsns() const {
    return mInsns;
}

void parallax::data::CodeItem::setInsns(uint8_t *insns) {
    CodeItem::mInsns = insns;
}

parallax::data::CodeItem::CodeItem(uint32_t methodIdx, uint32_t size,
                   uint8_t *insns): mMethodIdx(methodIdx), mInsnsSize(size), mInsns(insns) {

}

parallax::data::CodeItem::~CodeItem() {

}

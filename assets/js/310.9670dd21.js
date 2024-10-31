"use strict";
exports.id = 310;
exports.ids = [310];
exports.modules = {

/***/ 7310:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   count: () => (/* binding */ count),
/* harmony export */   getByID: () => (/* binding */ getByID)
/* harmony export */ });
function getByID(db, id) {
    return db.documentsStore.get(db.data.docs, id);
}
function count(db) {
    return db.documentsStore.count(db.data.docs);
}

//# sourceMappingURL=docs.js.map

/***/ })

};
;
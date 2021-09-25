/*
    path: /api/usuarios
*/


const { Router } = require('express');
const { check } = require('express-validator');
const { getUsuarios } = require('../controllers/usuarios');
const { validarJWT } = require('../middlewares/validar-jwt');


const router = Router();

router.get('/', validarJWT, getUsuarios);


module.exports = router;
const { response } = require("express");
const Usuario = require("../models/usuario");
const bcrypt = require('bcryptjs');
const { generarJWT } = require("../helpers/jwt");



const crearUsuario = async (req, res = response) => {

    const { email, password } = req.body;

    try{

        const existeEmail = await Usuario.findOne({ email });

        if(existeEmail){
            return res.status(400).json({
                ok: false,
                msg: 'El correo ya esta registrado.'
            })
        }

        const usuario = new Usuario(req.body);

        //Encriptar contraseña
        const salt = bcrypt.genSaltSync();
        usuario.password = bcrypt.hashSync(password, salt);

        await usuario.save();

        //Generar JWT
        const token = await generarJWT(usuario.id);

        res.json({
            ok: true,
            usuario,
            token
            //msg: 'Crear usuario!!!'
        });

    }catch(error){
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Hable con el administrador.'
        })
    }
}


const login = async (req, res = response) => {

    const { email, password } = req.body;

    try{

        const usuarioBD = await Usuario.findOne({ email });

        if( !usuarioBD ){
            return res.status(404).json({
                ok: false,
                msg: 'Email no encontrado.'
            });
        }

        //Validad Password
        const validPassword = bcrypt.compareSync( password, usuarioBD.password );
        if( !validPassword ){
            return res.status(400).json({
                ok: false,
                msg: 'La contraseña no es valida'
            });
        }

        //Generar JWT
        const token = await generarJWT( usuarioBD.id );

        res.json({
            ok: true,
            usuario: usuarioBD,
            token
            //msg: 'Crear usuario!!!'
        });
        
    }catch(error){
        console.log(error);
        return res.status(500).json({
            ok: false,
            msg: 'Hable con el administrador.'
        })
    }


    return res.json({
        ok: true,
        msg: 'login'
    })

}

const renewToken = async (req, res = response) => {

    const uid = req.uid;

    const token = await generarJWT( uid );

    const usuario = await Usuario.findById( uid );

    return res.json({
        ok: true,
        usuario,
        token
    })

}


module.exports = {
    crearUsuario,
    login,
    renewToken
}
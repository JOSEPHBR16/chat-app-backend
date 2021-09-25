const { comprobarJWT } = require('../helpers/jwt');
const { io } = require('../index');
const { usuarioConectado, usuarioDesconectado } = require('../controllers/socket');


// Mensajes de Sockets
io.on('connection', (client) => {
    console.log('Cliente conectado');

    const [valido, uid] = comprobarJWT( client.handshake.headers['x-token'] );

    if( !valido ) { return client.disconnect(); }

    //Cliente autenticado
    usuarioConectado( uid );

    console.log('cliente autenticado');

    client.on('disconnect', () => {
        usuarioDesconectado( uid );
    });

    // client.on('mensaje', ( payload ) => {
    //     console.log('Mensaje', payload);

    //     io.emit( 'mensaje', { admin: 'Nuevo mensaje' } );

    // });


});

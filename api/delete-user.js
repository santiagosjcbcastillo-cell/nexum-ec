const { admin, db, auth } = require('../lib/firebase-admin');


// =====================================================
// REGISTRO DE AUDITORÍA
// =====================================================

async function createSecurityLog(data) {

  await db.collection('securityLogs').add({

    ...data,

    timestamp:
      admin.firestore.FieldValue.serverTimestamp()

  });

}



module.exports = async function handler(req, res) {


  if (req.method !== 'POST') {

    return res.status(405).json({
      error:'Método no permitido'
    });

  }



  try {


    // =====================================================
    // 1. VALIDAR SESIÓN DEL ACTOR
    // =====================================================


    const authorization =
      req.headers.authorization || '';



    if (!authorization.startsWith('Bearer ')) {

      return res.status(401).json({
        error:'No autenticado'
      });

    }



    const idToken =
      authorization.substring(7);



    const decoded =
      await auth.verifyIdToken(idToken);



    const actorUid =
      decoded.uid;




    const actorDoc =
      await db
      .collection('users')
      .doc(actorUid)
      .get();




    if (!actorDoc.exists) {

      return res.status(403).json({
        error:'Usuario no autorizado'
      });

    }



    const actor =
      actorDoc.data();




    if (
      actor.active === false ||
      (actor.role !== 1 && actor.role !== 2)
    ) {

      return res.status(403).json({
        error:'Sin permisos'
      });

    }





    // =====================================================
    // 2. USUARIO OBJETIVO
    // =====================================================


    const { userId } =
      req.body || {};



    if (!userId) {

      return res.status(400).json({
        error:'Usuario requerido'
      });

    }




    // Evitar autoeliminación

    if (userId === actorUid) {

      return res.status(403).json({
        error:'No puede eliminar su propio usuario'
      });

    }





    const targetRef =
      db.collection('users')
      .doc(userId);




    const targetDoc =
      await targetRef.get();




    if (!targetDoc.exists) {

      return res.status(404).json({
        error:'Usuario no encontrado'
      });

    }




    const target =
      targetDoc.data();





    // =====================================================
    // 3. REGLAS DE ELIMINACIÓN
    // =====================================================


    // Nadie elimina SuperAdmin

    if (target.role === 1) {

      return res.status(403).json({
        error:'No puede eliminar administradores globales'
      });

    }




    // Oficial solo elimina usuarios de su notaría

    if (
      actor.role === 2 &&
      target.notariaId !== actor.notariaId
    ) {

      return res.status(403).json({
        error:'Usuario fuera de su notaría'
      });

    }





    // =====================================================
    // 4. ELIMINAR IDENTIDAD FIREBASE AUTH
    // =====================================================


    try {


      await auth.deleteUser(userId);



    } catch(error) {


      if (
        error.code !== 'auth/user-not-found'
      ) {

        throw error;

      }


    }





    // =====================================================
    // 5. ELIMINAR DATOS FIRESTORE
    // =====================================================


    const username =
      target.username;



    const batch =
      db.batch();




    batch.delete(
      db.collection('users')
      .doc(userId)
    );




    if (username) {


      batch.delete(

        db.collection('authCredentials')
        .doc(username.toLowerCase())

      );


    }




    await batch.commit();





    // =====================================================
    // 6. AUDITORÍA
    // =====================================================


    await createSecurityLog({


      action:
        'DELETE_USER',


      actorUid,


      targetUid:
        userId,


      username:
        target.username,


      roleDeleted:
        target.role,


      notariaId:
        target.notariaId || null


    });





    return res.status(200).json({

      success:true

    });





  } catch(error) {


    console.error(
      'Delete user error:',
      error
    );



    return res.status(500).json({

      error:
        'No fue posible eliminar usuario'

    });


  }


};

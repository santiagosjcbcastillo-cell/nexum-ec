const bcrypt = require('bcryptjs');
const { admin, db, auth } = require('../lib/firebase-admin');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Método no permitido'
    });
  }

  let createdUid = null;

  try {

    // =====================================================
    // 1. VERIFICAR SESIÓN FIREBASE
    // =====================================================

    const authorization = req.headers.authorization || '';

    if (!authorization.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'No autenticado'
      });
    }

    const idToken = authorization.substring(7);

    const decodedToken = await auth.verifyIdToken(idToken);

    const actorUid = decodedToken.uid;

    const actorDoc = await db
      .collection('users')
      .doc(actorUid)
      .get();

    if (!actorDoc.exists) {
      return res.status(403).json({
        error: 'Usuario no autorizado'
      });
    }

    const actor = actorDoc.data();

    if (actor.active === false) {
      return res.status(403).json({
        error: 'Usuario deshabilitado'
      });
    }

    // Solo SuperAdmin u Oficial
    if (actor.role !== 1 && actor.role !== 2) {
      return res.status(403).json({
        error: 'No tiene permisos para crear usuarios'
      });
    }

    // =====================================================
    // 2. VALIDAR DATOS
    // =====================================================

    const {
      nombre,
      username,
      password,
      role,
      notariaId
    } = req.body || {};

    if (
      typeof nombre !== 'string' ||
      typeof username !== 'string' ||
      typeof password !== 'string'
    ) {
      return res.status(400).json({
        error: 'Datos incompletos'
      });
    }

    const nombreLimpio = nombre.trim();
    const usernameNormalizado =
      username.trim().toLowerCase();

    const roleNumerico = Number(role);

    if (!nombreLimpio || !usernameNormalizado) {
      return res.status(400).json({
        error: 'Nombre y usuario son obligatorios'
      });
    }

    if (!/^[a-z0-9._-]{3,40}$/.test(usernameNormalizado)) {
      return res.status(400).json({
        error: 'El usuario contiene caracteres no permitidos'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: 'La contraseña debe tener al menos 8 caracteres'
      });
    }

    if (![1, 2, 3].includes(roleNumerico)) {
      return res.status(400).json({
        error: 'Rol inválido'
      });
    }

    // =====================================================
    // 3. CONTROL DE ROLES
    // =====================================================

    let notariaFinal = null;

    if (actor.role === 2) {

      // Oficial solo puede crear Matrizadores
      if (roleNumerico !== 3) {
        return res.status(403).json({
          error: 'El Oficial solo puede crear Matrizadores'
        });
      }

      notariaFinal = actor.notariaId;

    } else {

      // SuperAdmin
      if (roleNumerico !== 1) {

        if (!notariaId) {
          return res.status(400).json({
            error: 'Debe seleccionar una notaría'
          });
        }

        notariaFinal = notariaId;
      }
    }

    // =====================================================
    // 4. VERIFICAR NOTARÍA
    // =====================================================

    if (roleNumerico !== 1) {

      const notariaDoc = await db
        .collection('notarias')
        .doc(notariaFinal)
        .get();

      if (!notariaDoc.exists) {
        return res.status(400).json({
          error: 'La notaría seleccionada no existe'
        });
      }
    }

    // =====================================================
    // 5. VERIFICAR QUE EL USUARIO NO EXISTA
    // =====================================================

    const credentialRef = db
      .collection('authCredentials')
      .doc(usernameNormalizado);

    const credentialDoc = await credentialRef.get();

    if (credentialDoc.exists) {
      return res.status(409).json({
        error: 'El nombre de usuario ya está en uso'
      });
    }

    // También comprobar usuarios antiguos
    const usersSnap = await db
      .collection('users')
      .get();

    const usuarioExistente = usersSnap.docs.some(doc => {

      const existente = String(
        doc.data().username || ''
      )
        .trim()
        .toLowerCase();

      return existente === usernameNormalizado;
    });

    if (usuarioExistente) {
      return res.status(409).json({
        error: 'El nombre de usuario ya está en uso'
      });
    }

    // =====================================================
    // 6. CREAR UID
    // =====================================================

    const userRef = db
      .collection('users')
      .doc();

    createdUid = userRef.id;

    // =====================================================
    // 7. CREAR IDENTIDAD FIREBASE AUTH
    // =====================================================

    await auth.createUser({
      uid: createdUid,
      displayName: nombreLimpio,
      disabled: false
    });

    // =====================================================
    // 8. CIFRAR CONTRASEÑA
    // =====================================================

    const passwordHash = await bcrypt.hash(
      password,
      12
    );

    // =====================================================
    // 9. GUARDAR PERFIL + CREDENCIALES
    // =====================================================

    const batch = db.batch();

    batch.set(userRef, {
      nombre: nombreLimpio,
      username: usernameNormalizado,
      role: roleNumerico,
      notariaId: roleNumerico === 1
        ? null
        : notariaFinal,
      active: true,
      createdAt:
        admin.firestore.FieldValue.serverTimestamp(),
      createdBy: actorUid
    });

    batch.set(credentialRef, {
      uid: createdUid,
      username: usernameNormalizado,
      passwordHash,
      active: true,
      createdAt:
        admin.firestore.FieldValue.serverTimestamp()
    });

    await batch.commit();

    return res.status(201).json({
      success: true,
      user: {
        id: createdUid,
        nombre: nombreLimpio,
        username: usernameNormalizado,
        role: roleNumerico,
        notariaId:
          roleNumerico === 1
            ? null
            : notariaFinal,
        active: true
      }
    });

  } catch (error) {

    console.error(
      'Create user error:',
      error
    );

    // Si Firebase Auth se creó pero Firestore falló,
    // eliminar la identidad incompleta.
    if (createdUid) {
      try {
        await auth.deleteUser(createdUid);
      } catch (_) {}
    }

    return res.status(500).json({
      error: 'No fue posible crear el usuario'
    });
  }
};

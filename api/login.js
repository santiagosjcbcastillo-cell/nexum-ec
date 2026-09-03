const bcrypt = require('bcryptjs');
const { admin, db, auth } = require('../lib/firebase-admin');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Método no permitido'
    });
  }

  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== 'string' ||
      typeof password !== 'string' ||
      !username.trim() ||
      !password
    ) {
      return res.status(400).json({
        error: 'Datos incompletos'
      });
    }

    const usernameIngresado = username.trim();
    const usernameNormalizado = usernameIngresado.toLowerCase();

    let uid = null;
    let passwordValida = false;

    // =====================================================
    // 1. SISTEMA NUEVO
    // Contraseña protegida mediante bcrypt
    // =====================================================

    const credentialRef = db
      .collection('authCredentials')
      .doc(usernameNormalizado);

    const credentialDoc = await credentialRef.get();

    if (credentialDoc.exists) {
      const credential = credentialDoc.data();

      if (credential.active === false) {
        return res.status(401).json({
          error: 'Credenciales incorrectas'
        });
      }

      uid = credential.uid;

      if (
        !credential.passwordHash ||
        typeof credential.passwordHash !== 'string'
      ) {
        throw new Error('Credencial inválida');
      }

      passwordValida = await bcrypt.compare(
        password,
        credential.passwordHash
      );
    }

    // =====================================================
    // 2. MIGRACIÓN AUTOMÁTICA DE USUARIOS ANTIGUOS
    // =====================================================

    if (!credentialDoc.exists) {
      let usersSnap = await db
        .collection('users')
        .where('username', '==', usernameIngresado)
        .limit(1)
        .get();

      if (
        usersSnap.empty &&
        usernameIngresado !== usernameNormalizado
      ) {
        usersSnap = await db
          .collection('users')
          .where('username', '==', usernameNormalizado)
          .limit(1)
          .get();
      }

      if (!usersSnap.empty) {
        const userDoc = usersSnap.docs[0];
        const userData = userDoc.data();

        uid = userDoc.id;

        // Verificar contraseña antigua
        passwordValida =
          typeof userData.password === 'string' &&
          userData.password === password;

        if (passwordValida) {

          // ---------------------------------------------
          // Crear identidad Firebase Authentication
          // conservando el ID original
          // ---------------------------------------------
          try {
            await auth.getUser(uid);

          } catch (error) {

            if (error.code === 'auth/user-not-found') {
              await auth.createUser({
                uid,
                disabled: false
              });
            } else {
              throw error;
            }
          }

          // ---------------------------------------------
          // Generar hash seguro
          // ---------------------------------------------
          const passwordHash = await bcrypt.hash(
            password,
            12
          );

          // ---------------------------------------------
          // Migración atómica
          // ---------------------------------------------
          const batch = db.batch();

          batch.set(
            credentialRef,
            {
              uid,
              username: usernameNormalizado,
              passwordHash,
              active: userData.active !== false,
              migratedAt:
                admin.firestore.FieldValue.serverTimestamp()
            }
          );

          batch.update(
            db.collection('users').doc(uid),
            {
              username: usernameNormalizado,
              password:
                admin.firestore.FieldValue.delete(),
              active: userData.active !== false,
              migratedAt:
                admin.firestore.FieldValue.serverTimestamp()
            }
          );

          await batch.commit();
        }
      }
    }

    // =====================================================
    // 3. CREDENCIALES INCORRECTAS
    // =====================================================

    if (!uid || !passwordValida) {
      return res.status(401).json({
        error: 'Credenciales incorrectas'
      });
    }

    // =====================================================
    // 4. COMPROBAR PERFIL
    // =====================================================

    const profileDoc = await db
      .collection('users')
      .doc(uid)
      .get();

    if (!profileDoc.exists) {
      return res.status(401).json({
        error: 'Credenciales incorrectas'
      });
    }

    const profile = profileDoc.data();

    if (profile.active === false) {
      return res.status(401).json({
        error: 'Credenciales incorrectas'
      });
    }

    // =====================================================
    // 5. ASEGURAR IDENTIDAD FIREBASE AUTH
    // =====================================================

    try {
      const firebaseUser = await auth.getUser(uid);

      if (firebaseUser.disabled) {
        return res.status(401).json({
          error: 'Credenciales incorrectas'
        });
      }

    } catch (error) {

      if (error.code === 'auth/user-not-found') {
        await auth.createUser({
          uid,
          disabled: false
        });
      } else {
        throw error;
      }
    }

    // =====================================================
    // 6. CREAR TOKEN DE FIREBASE
    // =====================================================

    const token = await auth.createCustomToken(uid);

    return res.status(200).json({
      token
    });

  } catch (error) {
    console.error('Login error:', error);

    return res.status(500).json({
      error: 'No fue posible iniciar sesión'
    });
  }
};

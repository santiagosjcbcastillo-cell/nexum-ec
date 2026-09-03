const bcrypt = require('bcryptjs');
const { db, auth } = require('../lib/firebase-admin');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método no permitido' });
  }

  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== 'string' ||
      typeof password !== 'string' ||
      !username.trim() ||
      !password
    ) {
      return res.status(400).json({ error: 'Datos incompletos' });
    }

    const usernameIngresado = username.trim();
    const usernameNormalizado = usernameIngresado.toLowerCase();

    let uid = null;
    let passwordValida = false;

    // -------------------------------------------------
    // 1. NUEVO SISTEMA: contraseña cifrada con bcrypt
    // -------------------------------------------------
    const credentialDoc = await db
      .collection('authCredentials')
      .doc(usernameNormalizado)
      .get();

    if (credentialDoc.exists) {
      const credential = credentialDoc.data();

      if (credential.active === false) {
        return res.status(401).json({ error: 'Credenciales incorrectas' });
      }

      uid = credential.uid;

      passwordValida = await bcrypt.compare(
        password,
        credential.passwordHash
      );
    }

    // -------------------------------------------------
    // 2. MIGRACIÓN TEMPORAL:
    // permite entrar con usuarios antiguos mientras
    // todavía están guardados en la colección users.
    // -------------------------------------------------
    if (!credentialDoc.exists) {
      let usersSnap = await db
        .collection('users')
        .where('username', '==', usernameIngresado)
        .limit(1)
        .get();

      if (usersSnap.empty && usernameIngresado !== usernameNormalizado) {
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

        passwordValida =
          typeof userData.password === 'string' &&
          userData.password === password;

        // Crear identidad de Firebase Auth con el mismo ID
        // del usuario existente, si todavía no existe.
        if (passwordValida) {
          try {
            await auth.getUser(uid);
          } catch (error) {
            if (error.code === 'auth/user-not-found') {
              await auth.createUser({
                uid: uid,
                disabled: false
              });
            } else {
              throw error;
            }
          }
        }
      }
    }

    if (!uid || !passwordValida) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    // Verificar que el perfil siga existiendo
    const profileDoc = await db.collection('users').doc(uid).get();

    if (!profileDoc.exists) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const profile = profileDoc.data();

    if (profile.active === false) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    // Firebase crea una sesión real para este UID
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

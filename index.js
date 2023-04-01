import { config } from 'dotenv'
import express from 'express'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import { ObjectId } from 'mongodb'

import { connectToCluster } from './connectToCluster.js'
import { findAllUsers, createUser } from './services/index.js'

config()

const {
  PORT,
  DB_URI,
  JWT_SECRET,
  JWT_EXPIRES_IN,
  BCRYPT_SALT_ROUNDS
} = process.env

const app = express()

app.use(express.json())

const mongoClient = await connectToCluster(DB_URI)
const db = mongoClient.db('api-users')
const usersCollection = db.collection('users')

app.get('/api/users/all', async (req, res) => {
  try {
    const users = await findAllUsers(usersCollection)

    if (!users) return res.json({ error: 'any users found' })

    res.json(users)
  } catch (error) {
    res.json(error)
  }
})

app.post('/api/users', async (req, res) => {
  const { name, username, password } = req.body

  const user = await usersCollection.findOne({ username })

  if (user) return res.status(409).json({ error: 'there is already a user with the same name' })

  try {
    const hashPassword = await bcrypt.hash(password, Number(BCRYPT_SALT_ROUNDS))

    const newUser = {
      ...req.body,
      name,
      username,
      password: hashPassword
    }

    await usersCollection.insertOne(newUser)

    res.status(201).end()
  } catch (error) {
    res.status(404).json({ error: error.message })
  }
})

app.post('/api/users/auth', async (req, res) => {
  const { username, password } = req.body

  const user = await usersCollection.findOne({ username })

  const isPasswordCorrect = await bcrypt.compare(password, user.password)

  if (!user || !isPasswordCorrect) return res.status(401).json({ error: 'user or password incorrect' })

  const token = jwt.sign({ id: user._id.toString() }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN })

  res.json({ token })
})

app.get('/api/users', async (req, res) => {
  const { authorization } = req.headers

  try {
    const [, token] = authorization.split(' ')

    const { id: userId } = jwt.verify(token, JWT_SECRET)

    const user = await usersCollection.findOne({ _id: new ObjectId(userId) })

    if (!user) res.status(404).json({ error: 'user not found' })

    res.json({
      name: user.name,
      username: user.username
    })
  } catch (error) {
    res.status(400).end()
    console.log(error)
  }
})

app.patch('/api/users', async (req, res) => {
  const {
    headers: { authorization },
    body: { oldPassword, password }
  } = req

  try {
    const [, token] = authorization.split(' ')

    const { id: userId } = jwt.verify(token, JWT_SECRET)

    if (oldPassword && password) {
      const user = await usersCollection.findOne({ _id: new ObjectId(userId) })

      const isPasswordCorrect = await bcrypt.compare(oldPassword, user.password)

      if (!user || !isPasswordCorrect) return res.status(401).json({ error: 'user or password incorrect' })

      await usersCollection.updateOne(
        { _id: new ObjectId(userId) },
        {
          $set: {
            password: await bcrypt.hash(password, Number(BCRYPT_SALT_ROUNDS))
          }
        }
      )

      return res.status(204).end()
    }

    delete req.body.oldPassword
    delete req.body.password

    await usersCollection.updateOne(
      { _id: new ObjectId(userId) },
      {
        $set: {
          ...req.body
        }
      }
    )

    res.status(204).end()
  } catch (error) {
    res.status(400).end()
    console.log(error)
  }
})

app.delete('/api/users', async (req, res) => {
  const { headers: { authorization }, body: { password } } = req

  try {
    const [, token] = authorization.split(' ')

    const { id: userId } = jwt.verify(token, JWT_SECRET)

    const user = await usersCollection.findOne({ _id: new ObjectId(userId) })

    const isPasswordCorrect = await bcrypt.compare(password, user.password)

    if (!user || !isPasswordCorrect) return res.status(401).json({ error: 'user or password incorrect' })

    await usersCollection.deleteOne({ _id: new ObjectId(userId) })

    res.status(204).end()
  } catch (error) {
    res.status(404).end()
    console.log(error)
  }
})

app.listen(3000, () => {
  console.log(`Server listening on port ${PORT}`)
})

const express = require('express')
const router = express.Router()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const passport = require('passport')
const Mongoose = require('mongoose')
const multer = require('multer')

const auth = require('../middleware/auth')
const role = require('../middleware/role')
const store = require('../utils/store')
// Bring in Models & Helpers
const mailchimp = require('../services/mailchimp')
const mailgun = require('../services/mailgun')
const keys = require('../config/keys')
const {
  EMAIL_PROVIDER,
  JWT_COOKIE,
  ROLES,
  MERCHANT_STATUS,
  CART_ITEM_STATUS,
  REVIEW_STATUS
} = require('../constants')

const { secret, tokenLife } = keys.jwt
// Bring in Models & Helpers

//////////////////////
// Bring in Models & Utils
const User = require('../models/user')
const Address = require('../models/address')
const Brand = require('../models/brand')
const Product = require('../models/product')
const Merchant = require('../models/merchant')
const Cart = require('../models/cart')
const Category = require('../models/category')
const Contact = require('../models/contact')
const Order = require('../models/order')
const Review = require('../models/review')
const Wishlist = require('../models/wishlist')

//////////////////////

const checkAuth = require('../utils/auth')
const { s3Upload } = require('../utils/storage')
const {
  getStoreProductsQuery,
  getStoreProductsWishListQuery
} = require('../utils/queries')

const storage = multer.memoryStorage()
const upload = multer({ storage })
////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

// add address api
router.post('/address/add', auth, async (req, res) => {
  try {
    const user = req.user

    const address = new Address({
      ...req.body,
      user: user._id
    })
    const addressDoc = await address.save()

    res.status(200).json({
      success: true,
      message: `Address has been added successfully!`,
      address: addressDoc
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// fetch all addresses api
router.get('/address/', auth, async (req, res) => {
  try {
    const addresses = await Address.find({ user: req.user._id })

    res.status(200).json({
      addresses
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.get('/address/:id', async (req, res) => {
  try {
    const addressId = req.params.id

    const addressDoc = await Address.findOne({ _id: addressId })

    if (!addressDoc) {
      res.status(404).json({
        message: `Cannot find Address with the id: ${addressId}.`
      })
    }

    res.status(200).json({
      address: addressDoc
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.put('/address/:id', async (req, res) => {
  try {
    const addressId = req.params.id
    const update = req.body
    const query = { _id: addressId }

    await Address.findOneAndUpdate(query, update, {
      new: true
    })

    res.status(200).json({
      success: true,
      message: 'Address has been updated successfully!'
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.delete('/address/delete/:id', async (req, res) => {
  try {
    const address = await Address.deleteOne({ _id: req.params.id })

    res.status(200).json({
      success: true,
      message: `Address has been deleted successfully!`,
      address
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})
/////////////////////////
// authRoutes
///////////////////

router.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body

    if (!email) {
      return res.status(400).json({ error: 'You must enter an email address.' })
    }

    if (!password) {
      return res.status(400).json({ error: 'You must enter a password.' })
    }

    const user = await User.findOne({ email })
    if (!user) {
      return res
        .status(400)
        .send({ error: 'No user found for this email address.' })
    }

    if (user && user.provider !== EMAIL_PROVIDER.Email) {
      return res.status(400).send({
        error: `That email address is already in use using ${user.provider} provider.`
      })
    }

    const isMatch = await bcrypt.compare(password, user.password)

    if (!isMatch) {
      return res.status(400).json({
        success: false,
        error: 'Password Incorrect'
      })
    }

    const payload = {
      id: user.id
    }

    const token = jwt.sign(payload, secret, { expiresIn: tokenLife })

    if (!token) {
      throw new Error()
    }

    res.status(200).json({
      success: true,
      token: `Bearer ${token}`,
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role
      }
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.post('/auth/register', async (req, res) => {
  try {
    const { email, firstName, lastName, password, isSubscribed } = req.body

    if (!email) {
      return res.status(400).json({ error: 'You must enter an email address.' })
    }

    if (!firstName || !lastName) {
      return res.status(400).json({ error: 'You must enter your full name.' })
    }

    if (!password) {
      return res.status(400).json({ error: 'You must enter a password.' })
    }

    const existingUser = await User.findOne({ email })

    if (existingUser) {
      return res
        .status(400)
        .json({ error: 'That email address is already in use.' })
    }

    let subscribed = false
    if (isSubscribed) {
      const result = await mailchimp.subscribeToNewsletter(email)

      if (result.status === 'subscribed') {
        subscribed = true
      }
    }

    const user = new User({
      email,
      password,
      firstName,
      lastName
    })

    const salt = await bcrypt.genSalt(10)
    const hash = await bcrypt.hash(user.password, salt)

    user.password = hash
    const registeredUser = await user.save()

    const payload = {
      id: registeredUser.id
    }

    await mailgun.sendEmail(
      registeredUser.email,
      'signup',
      null,
      registeredUser
    )

    const token = jwt.sign(payload, secret, { expiresIn: tokenLife })

    res.status(200).json({
      success: true,
      subscribed,
      token: `Bearer ${token}`,
      user: {
        id: registeredUser.id,
        firstName: registeredUser.firstName,
        lastName: registeredUser.lastName,
        email: registeredUser.email,
        role: registeredUser.role
      }
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.post('/auth/forgot', async (req, res) => {
  try {
    const { email } = req.body

    if (!email) {
      return res.status(400).json({ error: 'You must enter an email address.' })
    }

    const existingUser = await User.findOne({ email })

    if (!existingUser) {
      return res
        .status(400)
        .send({ error: 'No user found for this email address.' })
    }

    const buffer = crypto.randomBytes(48)
    const resetToken = buffer.toString('hex')

    existingUser.resetPasswordToken = resetToken
    existingUser.resetPasswordExpires = Date.now() + 3600000

    existingUser.save()

    await mailgun.sendEmail(
      existingUser.email,
      'reset',
      req.headers.host,
      resetToken
    )

    res.status(200).json({
      success: true,
      message: 'Please check your email for the link to reset your password.'
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.post('/auth/reset/:token', async (req, res) => {
  try {
    const { password } = req.body

    if (!password) {
      return res.status(400).json({ error: 'You must enter a password.' })
    }

    const resetUser = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() }
    })

    if (!resetUser) {
      return res.status(400).json({
        error:
          'Your token has expired. Please attempt to reset your password again.'
      })
    }

    const salt = await bcrypt.genSalt(10)
    const hash = await bcrypt.hash(password, salt)

    resetUser.password = hash
    resetUser.resetPasswordToken = undefined
    resetUser.resetPasswordExpires = undefined

    resetUser.save()

    await mailgun.sendEmail(resetUser.email, 'reset-confirmation')

    res.status(200).json({
      success: true,
      message:
        'Password changed successfully. Please login with your new password.'
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.post('/auth/reset', auth, async (req, res) => {
  try {
    const { password, confirmPassword } = req.body
    const email = req.user.email

    if (!email) {
      return res.status(401).send('Unauthenticated')
    }

    if (!password) {
      return res.status(400).json({ error: 'You must enter a password.' })
    }

    const existingUser = await User.findOne({ email })
    if (!existingUser) {
      return res
        .status(400)
        .json({ error: 'That email address is already in use.' })
    }

    const isMatch = await bcrypt.compare(password, existingUser.password)

    if (!isMatch) {
      return res
        .status(400)
        .json({ error: 'Please enter your correct old password.' })
    }

    const salt = await bcrypt.genSalt(10)
    const hash = await bcrypt.hash(confirmPassword, salt)
    existingUser.password = hash
    existingUser.save()

    await mailgun.sendEmail(existingUser.email, 'reset-confirmation')

    res.status(200).json({
      success: true,
      message:
        'Password changed successfully. Please login with your new password.'
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.get(
  '/auth/google',
  passport.authenticate('google', {
    session: false,
    scope: ['profile', 'email'],
    accessType: 'offline',
    approvalPrompt: 'force'
  })
)

router.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: `${keys.app.clientURL}/login`,
    session: false
  }),
  (req, res) => {
    const payload = {
      id: req.user.id
    }

    // TODO find another way to send the token to frontend
    const token = jwt.sign(payload, secret, { expiresIn: tokenLife })
    const jwtToken = `Bearer ${token}`
    res.redirect(`${keys.app.clientURL}/auth/success?token=${jwtToken}`)
  }
)

router.get(
  '/auth/facebook',
  passport.authenticate('facebook', {
    session: false,
    scope: ['public_profile', 'email']
  })
)

router.get(
  '/auth/facebook/callback',
  passport.authenticate('facebook', {
    failureRedirect: `${keys.app.clientURL}/login`,
    session: false
  }),
  (req, res) => {
    const payload = {
      id: req.user.id
    }
    const token = jwt.sign(payload, secret, { expiresIn: tokenLife })
    const jwtToken = `Bearer ${token}`
    res.redirect(`${keys.app.clientURL}/auth/success?token=${jwtToken}`)
  }
)

/////////////////////////////
// /brand
/////////////////////////////

router.post('/brand/add', auth, role.check(ROLES.Admin), async (req, res) => {
  try {
    const name = req.body.name
    const description = req.body.description
    const isActive = req.body.isActive

    if (!description || !name) {
      return res
        .status(400)
        .json({ error: 'You must enter description & name.' })
    }

    const brand = new Brand({
      name,
      description,
      isActive
    })

    const brandDoc = await brand.save()

    res.status(200).json({
      success: true,
      message: `Brand has been added successfully!`,
      brand: brandDoc
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// fetch store brands api
router.get('/brand/list', async (req, res) => {
  try {
    const brands = await Brand.find({
      isActive: true
    }).populate('merchant', 'name')

    res.status(200).json({
      brands
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// fetch brands api
router.get(
  '/brand/',
  auth,
  role.check(ROLES.Admin, ROLES.Merchant),
  async (req, res) => {
    try {
      let brands = null

      if (req.user.merchant) {
        brands = await Brand.find({
          merchant: req.user.merchant
        }).populate('merchant', 'name')
      } else {
        brands = await Brand.find({}).populate('merchant', 'name')
      }

      res.status(200).json({
        brands
      })
    } catch (error) {
      res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }
  }
)

router.get('/brand/:id', async (req, res) => {
  try {
    const brandId = req.params.id

    const brandDoc = await Brand.findOne({ _id: brandId }).populate(
      'merchant',
      '_id'
    )

    if (!brandDoc) {
      return res.status(404).json({
        message: `Cannot find brand with the id: ${brandId}.`
      })
    }

    res.status(200).json({
      brand: brandDoc
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.get(
  '/brand/list/select',
  auth,
  role.check(ROLES.Admin, ROLES.Merchant),
  async (req, res) => {
    try {
      let brands = null

      if (req.user.merchant) {
        brands = await Brand.find(
          {
            merchant: req.user.merchant
          },
          'name'
        )
      } else {
        brands = await Brand.find({}, 'name')
      }

      res.status(200).json({
        brands
      })
    } catch (error) {
      res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }
  }
)

router.put(
  '/brand/:id',
  auth,
  role.check(ROLES.Admin, ROLES.Merchant),
  async (req, res) => {
    try {
      const brandId = req.params.id
      const update = req.body.brand
      const query = { _id: brandId }
      const { slug } = req.body.brand

      const foundBrand = await Brand.findOne({
        $or: [{ slug }]
      })

      if (foundBrand && foundBrand._id != brandId) {
        return res.status(400).json({ error: 'Slug is already in use.' })
      }

      await Brand.findOneAndUpdate(query, update, {
        new: true
      })

      res.status(200).json({
        success: true,
        message: 'Brand has been updated successfully!'
      })
    } catch (error) {
      res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }
  }
)

router.put(
  '/brand/:id/active',
  auth,
  role.check(ROLES.Admin, ROLES.Merchant),
  async (req, res) => {
    try {
      const brandId = req.params.id
      const update = req.body.brand
      const query = { _id: brandId }

      // disable brand(brandId) products
      if (!update.isActive) {
        const products = await Product.find({ brand: brandId })
        store.disableProducts(products)
      }

      await Brand.findOneAndUpdate(query, update, {
        new: true
      })

      res.status(200).json({
        success: true,
        message: 'Brand has been updated successfully!'
      })
    } catch (error) {
      res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }
  }
)

router.delete(
  '/brand/delete/:id',
  auth,
  role.check(ROLES.Admin),
  async (req, res) => {
    try {
      const brandId = req.params.id
      await deactivateMerchant(brandId)
      const brand = await Brand.deleteOne({ _id: brandId })

      res.status(200).json({
        success: true,
        message: `Brand has been deleted successfully!`,
        brand
      })
    } catch (error) {
      res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }
  }
)

const deactivateMerchant = async brandId => {
  const brandDoc = await Brand.findOne({ _id: brandId }).populate(
    'merchant',
    '_id'
  )
  if (!brandDoc || !brandDoc.merchant) return
  const merchantId = brandDoc.merchant._id
  const query = { _id: merchantId }
  const update = {
    status: MERCHANT_STATUS.Waiting_Approval,
    isActive: false,
    brand: null
  }
  return await Merchant.findOneAndUpdate(query, update, {
    new: true
  })
}
////////////////////////
// /cart
////////////////////////
router.post('/cart/add', auth, async (req, res) => {
  try {
    const user = req.user._id
    const items = req.body.products

    const products = store.caculateItemsSalesTax(items)

    const cart = new Cart({
      user,
      products
    })

    const cartDoc = await cart.save()

    decreaseQuantity(products)

    res.status(200).json({
      success: true,
      cartId: cartDoc.id
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.delete('/cart/delete/:cartId', auth, async (req, res) => {
  try {
    await Cart.deleteOne({ _id: req.params.cartId })

    res.status(200).json({
      success: true
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.post('/cart/add/:cartId', auth, async (req, res) => {
  try {
    const product = req.body.product
    const query = { _id: req.params.cartId }

    await Cart.updateOne(query, { $push: { products: product } }).exec()

    res.status(200).json({
      success: true
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.delete('/cart/delete/:cartId/:productId', auth, async (req, res) => {
  try {
    const product = { product: req.params.productId }
    const query = { _id: req.params.cartId }

    await Cart.updateOne(query, { $pull: { products: product } }).exec()

    res.status(200).json({
      success: true
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

const decreaseQuantity = products => {
  let bulkOptions = products.map(item => {
    return {
      updateOne: {
        filter: { _id: item.product },
        update: { $inc: { quantity: -item.quantity } }
      }
    }
  })

  Product.bulkWrite(bulkOptions)
}

///////////////////////////////////
// /category
///////////////////////////////////

router.post('/category/add', auth, role.check(ROLES.Admin), (req, res) => {
  const name = req.body.name
  const description = req.body.description
  const products = req.body.products
  const isActive = req.body.isActive

  if (!description || !name) {
    return res.status(400).json({ error: 'You must enter description & name.' })
  }

  const category = new Category({
    name,
    description,
    products,
    isActive
  })

  category.save((err, data) => {
    if (err) {
      return res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }

    res.status(200).json({
      success: true,
      message: `Category has been added successfully!`,
      category: data
    })
  })
})

// fetch store categories api
router.get('/category/list', async (req, res) => {
  try {
    const categories = await Category.find({ isActive: true })
    res.status(200).json({
      categories
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// fetch categories api
router.get('/category/', async (req, res) => {
  try {
    const categories = await Category.find({})
    res.status(200).json({
      categories
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// fetch category api
router.get('/category/:id', async (req, res) => {
  try {
    const categoryId = req.params.id

    const categoryDoc = await Category.findOne({ _id: categoryId }).populate({
      path: 'products',
      select: 'name'
    })

    if (!categoryDoc) {
      return res.status(404).json({
        message: 'No Category found.'
      })
    }

    res.status(200).json({
      category: categoryDoc
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.put('/category/:id', auth, role.check(ROLES.Admin), async (req, res) => {
  try {
    const categoryId = req.params.id
    const update = req.body.category
    const query = { _id: categoryId }
    const { slug } = req.body.category

    const foundCategory = await Category.findOne({
      $or: [{ slug }]
    })

    if (foundCategory && foundCategory._id != categoryId) {
      return res.status(400).json({ error: 'Slug is already in use.' })
    }

    await Category.findOneAndUpdate(query, update, {
      new: true
    })

    res.status(200).json({
      success: true,
      message: 'Category has been updated successfully!'
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.put(
  '/category/:id/active',
  auth,
  role.check(ROLES.Admin),
  async (req, res) => {
    try {
      const categoryId = req.params.id
      const update = req.body.category
      const query = { _id: categoryId }

      // disable category(categoryId) products
      if (!update.isActive) {
        const categoryDoc = await Category.findOne(
          { _id: categoryId, isActive: true },
          'products -_id'
        ).populate('products')

        store.disableProducts(categoryDoc.products)
      }

      await Category.findOneAndUpdate(query, update, {
        new: true
      })

      res.status(200).json({
        success: true,
        message: 'Category has been updated successfully!'
      })
    } catch (error) {
      res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }
  }
)

router.delete(
  '/category/delete/:id',
  auth,
  role.check(ROLES.Admin),
  async (req, res) => {
    try {
      const product = await Category.deleteOne({ _id: req.params.id })

      res.status(200).json({
        success: true,
        message: `Category has been deleted successfully!`,
        product
      })
    } catch (error) {
      res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }
  }
)

/////////////////////////////////////
// /contact
/////////////////////////////////////
router.post('/contact/add', async (req, res) => {
  try {
    const name = req.body.name
    const email = req.body.email
    const message = req.body.message

    if (!email) {
      return res.status(400).json({ error: 'You must enter an email address.' })
    }

    if (!name) {
      return res
        .status(400)
        .json({ error: 'You must enter description & name.' })
    }

    if (!message) {
      return res.status(400).json({ error: 'You must enter a message.' })
    }

    const existingContact = await Contact.findOne({ email })

    if (existingContact) {
      return res
        .status(400)
        .json({ error: 'A request already existed for same email address' })
    }

    const contact = new Contact({
      name,
      email,
      message
    })

    const contactDoc = await contact.save()

    await mailgun.sendEmail(email, 'contact')

    res.status(200).json({
      success: true,
      message: `We receved your message, we will reach you on your email address ${email}!`,
      contact: contactDoc
    })
  } catch (error) {
    return res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

//////////////////////////////////////
// /merchant
//////////////////////////////////////

// add merchant api
router.post('/merchant/add', async (req, res) => {
  try {
    const { name, business, phoneNumber, email, brandName } = req.body

    if (!name || !email) {
      return res
        .status(400)
        .json({ error: 'You must enter your name and email.' })
    }

    if (!business) {
      return res
        .status(400)
        .json({ error: 'You must enter a business description.' })
    }

    if (!phoneNumber || !email) {
      return res
        .status(400)
        .json({ error: 'You must enter a phone number and an email address.' })
    }

    const existingMerchant = await Merchant.findOne({ email })

    if (existingMerchant) {
      return res
        .status(400)
        .json({ error: 'That email address is already in use.' })
    }

    const merchant = new Merchant({
      name,
      email,
      business,
      phoneNumber,
      brandName
    })
    const merchantDoc = await merchant.save()

    await mailgun.sendEmail(email, 'merchant-application')

    res.status(200).json({
      success: true,
      message: `We received your request! we will reach you on your phone number ${phoneNumber}!`,
      merchant: merchantDoc
    })
  } catch (error) {
    return res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// search merchants api
router.get(
  '/merchant/search',
  auth,
  role.check(ROLES.Admin),
  async (req, res) => {
    try {
      const { search } = req.query

      const regex = new RegExp(search, 'i')

      const merchants = await Merchant.find({
        $or: [
          { phoneNumber: { $regex: regex } },
          { email: { $regex: regex } },
          { name: { $regex: regex } },
          { brandName: { $regex: regex } },
          { status: { $regex: regex } }
        ]
      }).populate('brand', 'name')

      res.status(200).json({
        merchants
      })
    } catch (error) {
      res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }
  }
)

// fetch all merchants api
router.get('/merchant/', auth, role.check(ROLES.Admin), async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query

    const merchants = await Merchant.find()
      .populate('brand')
      .sort('-created')
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec()

    const count = await Merchant.countDocuments()

    res.status(200).json({
      merchants,
      totalPages: Math.ceil(count / limit),
      currentPage: Number(page),
      count
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// disable merchant account
router.put('/merchant/:id/active', auth, async (req, res) => {
  try {
    const merchantId = req.params.id
    const update = req.body.merchant
    const query = { _id: merchantId }

    const merchantDoc = await Merchant.findOneAndUpdate(query, update, {
      new: true
    })

    if (!update.isActive) {
      await deactivateBrand(merchantId)
      await mailgun.sendEmail(merchantDoc.email, 'merchant-deactivate-account')
    }

    res.status(200).json({
      success: true
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// approve merchant
router.put('/merchant/approve/:id', auth, async (req, res) => {
  try {
    const merchantId = req.params.id
    const query = { _id: merchantId }
    const update = {
      status: MERCHANT_STATUS.Approved,
      isActive: true
    }

    const merchantDoc = await Merchant.findOneAndUpdate(query, update, {
      new: true
    })

    await createMerchantUser(
      merchantDoc.email,
      merchantDoc.name,
      merchantId,
      req.headers.host
    )

    res.status(200).json({
      success: true
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// reject merchant
router.put('/merchant/reject/:id', auth, async (req, res) => {
  try {
    const merchantId = req.params.id

    const query = { _id: merchantId }
    const update = {
      status: MERCHANT_STATUS.Rejected
    }

    await Merchant.findOneAndUpdate(query, update, {
      new: true
    })

    res.status(200).json({
      success: true
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.post('/merchant/signup/:token', async (req, res) => {
  try {
    const { email, firstName, lastName, password } = req.body

    if (!email) {
      return res.status(400).json({ error: 'You must enter an email address.' })
    }

    if (!firstName || !lastName) {
      return res.status(400).json({ error: 'You must enter your full name.' })
    }

    if (!password) {
      return res.status(400).json({ error: 'You must enter a password.' })
    }

    const userDoc = await User.findOne({
      email,
      resetPasswordToken: req.params.token
    })

    const salt = await bcrypt.genSalt(10)
    const hash = await bcrypt.hash(password, salt)

    const query = { _id: userDoc._id }
    const update = {
      email,
      firstName,
      lastName,
      password: hash,
      resetPasswordToken: undefined
    }

    await User.findOneAndUpdate(query, update, {
      new: true
    })

    const merchantDoc = await Merchant.findOne({
      email
    })

    await createMerchantBrand(merchantDoc)

    res.status(200).json({
      success: true
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.delete(
  '/merchant/delete/:id',
  auth,
  role.check(ROLES.Admin),
  async (req, res) => {
    try {
      const merchantId = req.params.id
      await deactivateBrand(merchantId)
      const merchant = await Merchant.deleteOne({ _id: merchantId })

      res.status(200).json({
        success: true,
        message: `Merchant has been deleted successfully!`,
        merchant
      })
    } catch (error) {
      res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }
  }
)

const deactivateBrand = async merchantId => {
  const merchantDoc = await Merchant.findOne({ _id: merchantId }).populate(
    'brand',
    '_id'
  )
  if (!merchantDoc || !merchantDoc.brand) return
  const brandId = merchantDoc.brand._id
  const query = { _id: brandId }
  const update = {
    isActive: false
  }
  return await Brand.findOneAndUpdate(query, update, {
    new: true
  })
}

const createMerchantBrand = async ({ _id, brandName, business }) => {
  const newBrand = new Brand({
    name: brandName,
    description: business,
    merchant: _id,
    isActive: false
  })

  const brandDoc = await newBrand.save()

  const update = {
    brand: brandDoc._id
  }
  await Merchant.findOneAndUpdate({ _id }, update)
}

const createMerchantUser = async (email, name, merchant, host) => {
  const firstName = name
  const lastName = ''

  const existingUser = await User.findOne({ email })

  if (existingUser) {
    const query = { _id: existingUser._id }
    const update = {
      merchant,
      role: ROLES.Merchant
    }

    const merchantDoc = await Merchant.findOne({
      email
    })

    await createMerchantBrand(merchantDoc)

    await mailgun.sendEmail(email, 'merchant-welcome', null, name)

    return await User.findOneAndUpdate(query, update, {
      new: true
    })
  } else {
    const buffer = await crypto.randomBytes(48)
    const resetToken = buffer.toString('hex')
    const resetPasswordToken = resetToken

    const user = new User({
      email,
      firstName,
      lastName,
      resetPasswordToken,
      merchant,
      role: ROLES.Merchant
    })

    await mailgun.sendEmail(email, 'merchant-signup', host, {
      resetToken,
      email
    })

    return await user.save()
  }
}

//////////////////////////////
// /newsletter
//////////////////////////////
router.post('/newsletter/subscribe', async (req, res) => {
  const email = req.body.email

  if (!email) {
    return res.status(400).json({ error: 'You must enter an email address.' })
  }

  const result = await mailchimp.subscribeToNewsletter(email)

  if (result.status === 400) {
    return res.status(400).json({ error: result.title })
  }

  await mailgun.sendEmail(email, 'newsletter-subscription')

  res.status(200).json({
    success: true,
    message: 'You have successfully subscribed to the newsletter'
  })
})

/////////////////////////
// /order
///////////////////////////

router.post('/order/add', auth, async (req, res) => {
  try {
    const cart = req.body.cartId
    const total = req.body.total
    const user = req.user._id

    const order = new Order({
      cart,
      user,
      total
    })

    const orderDoc = await order.save()

    const cartDoc = await Cart.findById(orderDoc.cart._id).populate({
      path: 'products.product',
      populate: {
        path: 'brand'
      }
    })

    const newOrder = {
      _id: orderDoc._id,
      created: orderDoc.created,
      user: orderDoc.user,
      total: orderDoc.total,
      products: cartDoc.products
    }

    await mailgun.sendEmail(order.user.email, 'order-confirmation', newOrder)

    res.status(200).json({
      success: true,
      message: `Your order has been placed successfully!`,
      order: { _id: orderDoc._id }
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// search orders api
router.get('/order/search', auth, async (req, res) => {
  try {
    const { search } = req.query

    if (!Mongoose.Types.ObjectId.isValid(search)) {
      return res.status(200).json({
        orders: []
      })
    }

    let ordersDoc = null

    if (req.user.role === ROLES.Admin) {
      ordersDoc = await Order.find({
        _id: Mongoose.Types.ObjectId(search)
      }).populate({
        path: 'cart',
        populate: {
          path: 'products.product',
          populate: {
            path: 'brand'
          }
        }
      })
    } else {
      const user = req.user._id
      ordersDoc = await Order.find({
        _id: Mongoose.Types.ObjectId(search),
        user
      }).populate({
        path: 'cart',
        populate: {
          path: 'products.product',
          populate: {
            path: 'brand'
          }
        }
      })
    }

    ordersDoc = ordersDoc.filter(order => order.cart)

    if (ordersDoc.length > 0) {
      const newOrders = ordersDoc.map(o => {
        return {
          _id: o._id,
          total: parseFloat(Number(o.total.toFixed(2))),
          created: o.created,
          products: o.cart?.products
        }
      })

      let orders = newOrders.map(o => store.caculateTaxAmount(o))
      orders.sort((a, b) => b.created - a.created)
      res.status(200).json({
        orders
      })
    } else {
      res.status(200).json({
        orders: []
      })
    }
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// fetch orders api
router.get('/order/', auth, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query
    const ordersDoc = await Order.find()
      .sort('-created')
      .populate({
        path: 'cart',
        populate: {
          path: 'products.product',
          populate: {
            path: 'brand'
          }
        }
      })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec()

    const count = await Order.countDocuments()
    const orders = store.formatOrders(ordersDoc)

    res.status(200).json({
      orders,
      totalPages: Math.ceil(count / limit),
      currentPage: Number(page),
      count
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// fetch my orders api
router.get('/order/me', auth, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query
    const user = req.user._id
    const query = { user }

    const ordersDoc = await Order.find(query)
      .sort('-created')
      .populate({
        path: 'cart',
        populate: {
          path: 'products.product',
          populate: {
            path: 'brand'
          }
        }
      })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec()

    const count = await Order.countDocuments(query)
    const orders = store.formatOrders(ordersDoc)

    res.status(200).json({
      orders,
      totalPages: Math.ceil(count / limit),
      currentPage: Number(page),
      count
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// fetch order api
router.get('/order/:orderId', auth, async (req, res) => {
  try {
    const orderId = req.params.orderId

    let orderDoc = null

    if (req.user.role === ROLES.Admin) {
      orderDoc = await Order.findOne({ _id: orderId }).populate({
        path: 'cart',
        populate: {
          path: 'products.product',
          populate: {
            path: 'brand'
          }
        }
      })
    } else {
      const user = req.user._id
      orderDoc = await Order.findOne({ _id: orderId, user }).populate({
        path: 'cart',
        populate: {
          path: 'products.product',
          populate: {
            path: 'brand'
          }
        }
      })
    }

    if (!orderDoc || !orderDoc.cart) {
      return res.status(404).json({
        message: `Cannot find order with the id: ${orderId}.`
      })
    }

    let order = {
      _id: orderDoc._id,
      total: orderDoc.total,
      created: orderDoc.created,
      totalTax: 0,
      products: orderDoc?.cart?.products,
      cartId: orderDoc.cart._id
    }

    order = store.caculateTaxAmount(order)

    res.status(200).json({
      order
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.delete('/order/cancel/:orderId', auth, async (req, res) => {
  try {
    const orderId = req.params.orderId

    const order = await Order.findOne({ _id: orderId })
    const foundCart = await Cart.findOne({ _id: order.cart })

    increaseQuantity(foundCart.products)

    await Order.deleteOne({ _id: orderId })
    await Cart.deleteOne({ _id: order.cart })

    res.status(200).json({
      success: true
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.put('/order/status/item/:itemId', auth, async (req, res) => {
  try {
    const itemId = req.params.itemId
    const orderId = req.body.orderId
    const cartId = req.body.cartId
    const status = req.body.status || CART_ITEM_STATUS.Cancelled

    const foundCart = await Cart.findOne({ 'products._id': itemId })
    const foundCartProduct = foundCart.products.find(p => p._id == itemId)

    await Cart.updateOne(
      { 'products._id': itemId },
      {
        'products.$.status': status
      }
    )

    if (status === CART_ITEM_STATUS.Cancelled) {
      await Product.updateOne(
        { _id: foundCartProduct.product },
        { $inc: { quantity: foundCartProduct.quantity } }
      )

      const cart = await Cart.findOne({ _id: cartId })
      const items = cart.products.filter(
        item => item.status === CART_ITEM_STATUS.Cancelled
      )

      // All items are cancelled => Cancel order
      if (cart.products.length === items.length) {
        await Order.deleteOne({ _id: orderId })
        await Cart.deleteOne({ _id: cartId })

        return res.status(200).json({
          success: true,
          orderCancelled: true,
          message: `${
            req.user.role === ROLES.Admin ? 'Order' : 'Your order'
          } has been cancelled successfully`
        })
      }

      return res.status(200).json({
        success: true,
        message: 'Item has been cancelled successfully!'
      })
    }

    res.status(200).json({
      success: true,
      message: 'Item status has been updated successfully!'
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

const increaseQuantity = products => {
  let bulkOptions = products.map(item => {
    return {
      updateOne: {
        filter: { _id: item.product },
        update: { $inc: { quantity: item.quantity } }
      }
    }
  })

  Product.bulkWrite(bulkOptions)
}

//////////////////////////////////////
// /product
////////////////////////////////////

// fetch product slug api
router.get('/product/item/:slug', async (req, res) => {
  try {
    const slug = req.params.slug

    const productDoc = await Product.findOne({ slug, isActive: true }).populate(
      {
        path: 'brand',
        select: 'name isActive slug'
      }
    )

    const hasNoBrand =
      productDoc?.brand === null || productDoc?.brand?.isActive === false

    if (!productDoc || hasNoBrand) {
      return res.status(404).json({
        message: 'No product found.'
      })
    }

    res.status(200).json({
      product: productDoc
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// fetch product name search api
router.get('/product/list/search/:name', async (req, res) => {
  try {
    const name = req.params.name

    const productDoc = await Product.find(
      { name: { $regex: new RegExp(name), $options: 'is' }, isActive: true },
      { name: 1, slug: 1, imageUrl: 1, price: 1, _id: 0 }
    )

    if (productDoc.length < 0) {
      return res.status(404).json({
        message: 'No product found.'
      })
    }

    res.status(200).json({
      products: productDoc
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// fetch store products by advanced filters api
router.get('/product/list', async (req, res) => {
  try {
    let {
      sortOrder,
      rating,
      max,
      min,
      category,
      brand,
      page = 1,
      limit = 10
    } = req.query
    sortOrder = JSON.parse(sortOrder)

    const categoryFilter = category ? { category } : {}
    const basicQuery = getStoreProductsQuery(min, max, rating)

    const userDoc = await checkAuth(req)
    const categoryDoc = await Category.findOne({
      slug: categoryFilter.category,
      isActive: true
    })

    if (categoryDoc) {
      basicQuery.push({
        $match: {
          isActive: true,
          _id: {
            $in: Array.from(categoryDoc.products)
          }
        }
      })
    }

    const brandDoc = await Brand.findOne({
      slug: brand,
      isActive: true
    })

    if (brandDoc) {
      basicQuery.push({
        $match: {
          'brand._id': { $eq: brandDoc._id }
        }
      })
    }

    let products = null
    const productsCount = await Product.aggregate(basicQuery)
    const count = productsCount.length
    const size = count > limit ? page - 1 : 0
    const currentPage = count > limit ? Number(page) : 1

    // paginate query
    const paginateQuery = [
      { $sort: sortOrder },
      { $skip: size * limit },
      { $limit: limit * 1 }
    ]

    if (userDoc) {
      const wishListQuery = getStoreProductsWishListQuery(userDoc.id).concat(
        basicQuery
      )
      products = await Product.aggregate(wishListQuery.concat(paginateQuery))
    } else {
      products = await Product.aggregate(basicQuery.concat(paginateQuery))
    }

    res.status(200).json({
      products,
      totalPages: Math.ceil(count / limit),
      currentPage,
      count
    })
  } catch (error) {
    console.log('error', error)
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.get('/product/list/select', auth, async (req, res) => {
  try {
    const products = await Product.find({}, 'name')

    res.status(200).json({
      products
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// add product api
router.post(
  '/product/add',
  auth,
  role.check(ROLES.Admin, ROLES.Merchant),
  upload.single('image'),
  async (req, res) => {
    try {
      const sku = req.body.sku
      const name = req.body.name
      const description = req.body.description
      const quantity = req.body.quantity
      const price = req.body.price
      const taxable = req.body.taxable
      const isActive = req.body.isActive
      const brand = req.body.brand
      const image = req.file

      if (!sku) {
        return res.status(400).json({ error: 'You must enter sku.' })
      }

      if (!description || !name) {
        return res
          .status(400)
          .json({ error: 'You must enter description & name.' })
      }

      if (!quantity) {
        return res.status(400).json({ error: 'You must enter a quantity.' })
      }

      if (!price) {
        return res.status(400).json({ error: 'You must enter a price.' })
      }

      const foundProduct = await Product.findOne({ sku })

      if (foundProduct) {
        return res.status(400).json({ error: 'This sku is already in use.' })
      }

      const { imageUrl, imageKey } = await s3Upload(image)

      const product = new Product({
        sku,
        name,
        description,
        quantity,
        price,
        taxable,
        isActive,
        brand,
        imageUrl,
        imageKey
      })

      const savedProduct = await product.save()

      res.status(200).json({
        success: true,
        message: `Product has been added successfully!`,
        product: savedProduct
      })
    } catch (error) {
      return res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }
  }
)

// fetch products api
router.get(
  '/product/',
  auth,
  role.check(ROLES.Admin, ROLES.Merchant),
  async (req, res) => {
    try {
      let products = []

      if (req.user.merchant) {
        const brands = await Brand.find({
          merchant: req.user.merchant
        }).populate('merchant', '_id')

        const brandId = brands[0]?.['_id']

        products = await Product.find({})
          .populate({
            path: 'brand',
            populate: {
              path: 'merchant',
              model: 'Merchant'
            }
          })
          .where('brand', brandId)
      } else {
        products = await Product.find({}).populate({
          path: 'brand',
          populate: {
            path: 'merchant',
            model: 'Merchant'
          }
        })
      }

      res.status(200).json({
        products
      })
    } catch (error) {
      res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }
  }
)

// fetch product api
router.get(
  '/product/:id',
  auth,
  role.check(ROLES.Admin, ROLES.Merchant),
  async (req, res) => {
    try {
      const productId = req.params.id

      let productDoc = null

      if (req.user.merchant) {
        const brands = await Brand.find({
          merchant: req.user.merchant
        }).populate('merchant', '_id')

        const brandId = brands[0]['_id']

        productDoc = await Product.findOne({ _id: productId })
          .populate({
            path: 'brand',
            select: 'name'
          })
          .where('brand', brandId)
      } else {
        productDoc = await Product.findOne({ _id: productId }).populate({
          path: 'brand',
          select: 'name'
        })
      }

      if (!productDoc) {
        return res.status(404).json({
          message: 'No product found.'
        })
      }

      res.status(200).json({
        product: productDoc
      })
    } catch (error) {
      res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }
  }
)

router.put(
  '/product/:id',
  auth,
  role.check(ROLES.Admin, ROLES.Merchant),
  async (req, res) => {
    try {
      const productId = req.params.id
      const update = req.body.product
      const query = { _id: productId }
      const { sku, slug } = req.body.product

      const foundProduct = await Product.findOne({
        $or: [{ slug }, { sku }]
      })

      if (foundProduct && foundProduct._id != productId) {
        return res.status(400).json({ error: 'Sku or slug is already in use.' })
      }

      await Product.findOneAndUpdate(query, update, {
        new: true
      })

      res.status(200).json({
        success: true,
        message: 'Product has been updated successfully!'
      })
    } catch (error) {
      res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }
  }
)

router.put(
  '/product/:id/active',
  auth,
  role.check(ROLES.Admin, ROLES.Merchant),
  async (req, res) => {
    try {
      const productId = req.params.id
      const update = req.body.product
      const query = { _id: productId }

      await Product.findOneAndUpdate(query, update, {
        new: true
      })

      res.status(200).json({
        success: true,
        message: 'Product has been updated successfully!'
      })
    } catch (error) {
      res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }
  }
)

router.delete(
  '/product/delete/:id',
  auth,
  role.check(ROLES.Admin, ROLES.Merchant),
  async (req, res) => {
    try {
      const product = await Product.deleteOne({ _id: req.params.id })

      res.status(200).json({
        success: true,
        message: `Product has been deleted successfully!`,
        product
      })
    } catch (error) {
      res.status(400).json({
        error: 'Your request could not be processed. Please try again.'
      })
    }
  }
)

///////////////////////////////////////////////////////
// /review
////////////////////////////////////////////////////

router.post('/review/add', auth, async (req, res) => {
  try {
    const user = req.user

    const review = new Review({
      ...req.body,
      user: user._id
    })

    const reviewDoc = await review.save()

    res.status(200).json({
      success: true,
      message: `Your review has been added successfully and will appear when approved!`,
      review: reviewDoc
    })
  } catch (error) {
    return res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// fetch all reviews api
router.get('/review/', async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query

    const reviews = await Review.find()
      .sort('-created')
      .populate({
        path: 'user',
        select: 'firstName'
      })
      .populate({
        path: 'product',
        select: 'name slug imageUrl'
      })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec()

    const count = await Review.countDocuments()

    res.status(200).json({
      reviews,
      totalPages: Math.ceil(count / limit),
      currentPage: Number(page),
      count
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.get('/review/:slug', async (req, res) => {
  try {
    const productDoc = await Product.findOne({ slug: req.params.slug })

    const hasNoBrand =
      productDoc?.brand === null || productDoc?.brand?.isActive === false

    if (!productDoc || hasNoBrand) {
      return res.status(404).json({
        message: 'No product found.'
      })
    }

    const reviews = await Review.find({
      product: productDoc._id,
      status: REVIEW_STATUS.Approved
    })
      .populate({
        path: 'user',
        select: 'firstName'
      })
      .sort('-created')

    res.status(200).json({
      reviews
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.put('/review/:id', async (req, res) => {
  try {
    const reviewId = req.params.id
    const update = req.body
    const query = { _id: reviewId }

    await Review.findOneAndUpdate(query, update, {
      new: true
    })

    res.status(200).json({
      success: true,
      message: 'review has been updated successfully!'
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// approve review
router.put('/review/approve/:reviewId', auth, async (req, res) => {
  try {
    const reviewId = req.params.reviewId

    const query = { _id: reviewId }
    const update = {
      status: REVIEW_STATUS.Approved,
      isActive: true
    }

    await Review.findOneAndUpdate(query, update, {
      new: true
    })

    res.status(200).json({
      success: true
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// reject review
router.put('/review/reject/:reviewId', auth, async (req, res) => {
  try {
    const reviewId = req.params.reviewId

    const query = { _id: reviewId }
    const update = {
      status: REVIEW_STATUS.Rejected
    }

    await Review.findOneAndUpdate(query, update, {
      new: true
    })

    res.status(200).json({
      success: true
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.delete('/review/delete/:id', async (req, res) => {
  try {
    const review = await Review.deleteOne({ _id: req.params.id })

    res.status(200).json({
      success: true,
      message: `review has been deleted successfully!`,
      review
    })
  } catch (error) {
    return res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

////////////////////////////////////////////////////////
// /user
///////////////////////////////////////////////////////

// search users api
router.get('/user/search', auth, role.check(ROLES.Admin), async (req, res) => {
  try {
    const { search } = req.query

    const regex = new RegExp(search, 'i')

    const users = await User.find(
      {
        $or: [
          { firstName: { $regex: regex } },
          { lastName: { $regex: regex } },
          { email: { $regex: regex } }
        ]
      },
      { password: 0, _id: 0 }
    ).populate('merchant', 'name')

    res.status(200).json({
      users
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// fetch users api
router.get('/user/', auth, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query

    const users = await User.find({}, { password: 0, _id: 0, googleId: 0 })
      .sort('-created')
      .populate('merchant', 'name')
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec()

    const count = await User.countDocuments()

    res.status(200).json({
      users,
      totalPages: Math.ceil(count / limit),
      currentPage: Number(page),
      count
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.get('/user/me', auth, async (req, res) => {
  try {
    const user = req.user._id
    const userDoc = await User.findById(user, { password: 0 }).populate({
      path: 'merchant',
      model: 'Merchant',
      populate: {
        path: 'brand',
        model: 'Brand'
      }
    })

    res.status(200).json({
      user: userDoc
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

router.put('/user/', auth, async (req, res) => {
  try {
    const user = req.user._id
    const update = req.body.profile
    const query = { _id: user }

    const userDoc = await User.findOneAndUpdate(query, update, {
      new: true
    })

    res.status(200).json({
      success: true,
      message: 'Your profile is successfully updated!',
      user: userDoc
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

//////////////////////////////////////////////////////
// /wishlist
//////////////////////////////////////////////////////

router.post('/wishlist/', auth, async (req, res) => {
  try {
    const { product, isLiked } = req.body
    const user = req.user
    const update = {
      product,
      isLiked,
      updated: Date.now()
    }
    const query = { product: update.product, user: user._id }

    const updatedWishlist = await Wishlist.findOneAndUpdate(query, update, {
      new: true
    })

    if (updatedWishlist !== null) {
      res.status(200).json({
        success: true,
        message: 'Your Wishlist has been updated successfully!',
        wishlist: updatedWishlist
      })
    } else {
      const wishlist = new Wishlist({
        product,
        isLiked,
        user: user._id
      })

      const wishlistDoc = await wishlist.save()

      res.status(200).json({
        success: true,
        message: `Added to your Wishlist successfully!`,
        wishlist: wishlistDoc
      })
    }
  } catch (e) {
    return res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

// fetch wishlist api
router.get('/wishlist/', auth, async (req, res) => {
  try {
    const user = req.user._id

    const wishlist = await Wishlist.find({ user, isLiked: true })
      .populate({
        path: 'product',
        select: 'name slug price imageUrl'
      })
      .sort('-updated')

    res.status(200).json({
      wishlist
    })
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    })
  }
})

module.exports = router

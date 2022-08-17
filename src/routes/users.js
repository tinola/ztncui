/*
  ztncui - ZeroTier network controller UI
  Copyright (C) 2017-2021  Key Networks (https://key-networks.com)
  Licensed under GPLv3 - see LICENSE for details.
*/

const express = require('express');
const router = express.Router();
const { restrict, restrictSuperAdmin } = require('../controllers/auth');
const usersController = require('../controllers/usersController');

// GET request for users
router.get('/', restrict, restrictSuperAdmin, usersController.users_list);

// GET request for password
router.get('/:name/password', restrict, restrictSuperAdmin, usersController.password_get);

// POST request for password
router.post('/:name/password', restrict, restrictSuperAdmin, usersController.password_post);

// GET request for user create
router.get('/create', restrict, restrictSuperAdmin, usersController.user_create_get);

// POST request for user create
router.post('/create', restrict, restrictSuperAdmin, usersController.user_create_post);

// GET request for user delete
router.get('/:name/delete', restrict, restrictSuperAdmin, usersController.user_delete);

// POST request for user delete
router.post('/:name/delete', restrict, restrictSuperAdmin, usersController.user_delete);

module.exports = router;

const router = require("express").Router();
const pass_generator = require("generate-password");
const { User, validate } = require("../models/User");
const { UserRoleConstants, PathUrlConstant, PermissionsCodesConstant, PermissionsKeysConstant, ChatEventConstant } = require("../utils/const");
const HelperUtils = require("../utils/helpers");
const adminAuth = require("../middleware/admin")
const auth = require("../middleware/auth")
const { AdminPermissionMaster, AdminRoleMaster, AdminManage } = require("../models/Admin");
const { Company } = require("../models/Company")
const bcrypt = require("bcryptjs");
const _ = require("lodash");
const Joi = require("joi");
const config = require("config");
const EmailController = require("../controller/Email.controller");
const { path, create } = require("d3");
const { getChildUser, checkPermission } = require("../controller/Admin.controller");
const { FileUpload } = require("../models/FileUpload");
const { Registration } = require("../models/Registration");
const { ParentTeam, Team } = require("../models/Team");
const { BCDeviceData, BCEvent, BCDeviceColumnMap } = require("../models/BCImport");
const AdminController = require('./../controller/Admin.controller')
const { parse } = require('json2csv');
const fs = require('fs');
const { Event } = require("../models/Event");
const { Group } = require("../models/Group");
const { GroupSubscriber } = require("../models/GroupSubscriber");
const groupHandler = require('./../social-socket/handler/groupHandler');
const { AddTaskToExportProcessingQueue } = require("../startup/queue-management");

function validateLogin(User) {
    const schema = {
        email: Joi.string().required(),
        password: Joi.string().required()
    };
    return Joi.validate(User, schema);
}



/**
 * @typedef AdminLogin
 * @property {string} email.required
 * @property {string} password.required
 */

/**
 * Admin Login
 * @route POST /admin/login
 * @param {AdminLogin.model} AdminLogin.body.required - admin login object
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Jwt Token in key result.token
 *      
 * @returns {Error}  Error - Unexpected error
 */
router.post("/login", async (req, res) => {
    const { error } = validateLogin(req.body);
    if (error) {
        res.status(400).send(HelperUtils.errorObj(error.details[0].message));
        return;
    }
    let user = await User.findOne({
        $and: [{ $or: [{ email: req.body.email.toLowerCase() }, { username: req.body.email.toLowerCase() }] },
        { role: { $in: [UserRoleConstants.ADMIN, UserRoleConstants.SUPER_ADMIN] } }]
    });
    if (!user) {
        res.status(400).send(HelperUtils.errorObj("Invalid Email or Password"));
        return;
    }
    var adminROle = [UserRoleConstants.SUPER_ADMIN, UserRoleConstants.ADMIN];
    if (user && user.role && !adminROle.includes(user.role)) {
        res.status(400).send(HelperUtils.errorObj("InValid Role"));
        return;
    }


    const isValid = await bcrypt.compare(req.body.password, user.password);
    if (!isValid && req.body.password) {   //remove master pwd DMCN 630
        res.status(400).send(HelperUtils.errorObj("Invalid Email or Password"));
        return;
    }

    res.send(HelperUtils.successObj("Logged In ", await user.generateAuthToken()));
});




/**
 * @typedef NewAdmin
 * @property {string} email.required
 * @property {string} username.required
 * @property {string} fname.required
 * @property {string} lname.required
 */

/**
 * Create New Admin
 * @route POST /admin/create
 * @param {NewAdmin.model} NewAdmin.body.required - admin login object
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Jwt Token in key result.token
 *      
 * @returns {Error}  Error - Unexpected error
 */


router.post("/create", async (req, res) => {


    let admin = await User.findOne({ email: req.body.email, role: { $in: [UserRoleConstants.ADMIN, UserRoleConstants.SUPER_ADMIN] } })
    if (admin) {
        res.status(400).send(HelperUtils.errorObj("THis email already exsit try new."));
        return;
    }

    const salt = await bcrypt.genSalt(10);
    req.body.password = pass_generator.generate({
        length: 8,
        numbers: true
    });//"Diamond1#";
    var decryped_pass = req.body.password;
    req.body.password = await bcrypt.hash(req.body.password, salt);
    var user = new User({
        fname: req.body.fname,
        lname: req.body.lname,
        email: req.body.email.toLowerCase(),
        password: req.body.password,
        pass: decryped_pass,
        phone: HelperUtils.generateRandomNumber(),
        username: req.body.username,
        role: UserRoleConstants.ADMIN
    });
    await user.save();
    console.log("--create-->>", req.body);
    EmailController.sendEmailForSubAdminCreation({ email: req.body.email.toLowerCase(), password: decryped_pass })

    res.status(200).send(HelperUtils.successObj(user));


    return;
});




/**
 * @typedef AdminPasswordChange
 * @property {string} email.required
 * @property {string} oldpassword.required
 * @property {string} newpassword.required
 */

/**
 * Admin Login
 * @route POST /admin/password/change
 * @param {AdminPasswordChange.model} AdminPasswordChange.body.required - admin login object
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Jwt Token in key result.token
 *      
 * @returns {Error}  Error - Unexpected error
 */


router.post("/password/change", async (req, res) => {

    let userObj = await User.findOne({ email: req.body.email.toLowerCase(), role: { $in: [UserRoleConstants.ADMIN, UserRoleConstants.SUPER_ADMIN] } });
    if (!userObj) {
        res.status(400).send(HelperUtils.errorObj("Invalid Email or password"));
        return;
    }

    const isValid = await bcrypt.compare(req.body.oldpassword, userObj.password);
    if (!isValid) {
        res.status(400).send(HelperUtils.errorObj("Old Password Not Valid"));
        return;
    }
    const salt = await bcrypt.genSalt(10);
    userObj.password = await bcrypt.hash(req.body.newpassword, salt);

    await userObj.save();

    res.status(200).send(HelperUtils.successObj("Password Updated"));
    return;
});


/**
 * @typedef AdminPasswordReset
 * @property {string} email.required
 * @property {string} newpassword.required
 * @property {string} conpassword.required
 */

/**
 * Admin Login
 * @route POST /admin/password/passreset
 * @param {AdminPasswordReset.model} AdminPasswordReset.body.required - admin login object
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Jwt Token in key result.token
 *      
 * @returns {Error}  Error - Unexpected error
 */


router.post("/password/passreset", async (req, res) => {
    let userObj = await User.findOne({ email: req.body.email.toLowerCase(), $or: [{ role: "Admin" }, { role: "Super Admin" }]/*, role: { $in: [UserRoleConstants.ADMIN, UserRoleConstants.SUPER_ADMIN] }*/ });
    if (!userObj) {
        res.status(400).send(HelperUtils.errorObj("Invalid Email or Password"));
        return;
    }

    // const isValid = await bcrypt.compare(req.body.conpassword, req.body.newpassword);
    // if (!isValid) {
    //   res.status(400).send(HelperUtils.errorObj("Not match new password and confirm password."));
    //   return;
    // }
    const salt = await bcrypt.genSalt(10);
    userObj.password = await bcrypt.hash(req.body.newpassword, salt);

    await userObj.save();

    let sendemail = await EmailController.ressetpasswordUser(userObj._id, req.body.newpassword)
    res.status(200).send(HelperUtils.successObj("Password Reset"));
    return;
});

/**
 * @typedef UpdateAdmin
 * @property {string} adminId
 * @property {string} fname
 * @property {string} lname
 * @property {string} email
 * @property {string} profileUrl
 * @property {string} username
 */

/**
 * Admin User update
 * @route POST /admin/user/update
 * @param {UpdateAdmin.model} UpdateAdmin.body.required - admin update object
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return admin obj
 * @returns {Error}  Error - Unexpected error
 * @security Admin
 */


router.post("/user/update", [auth, adminAuth], async (req, res) => {
    let userObj = await User.findById(req.body.adminId);
    if (!userObj) {
        res.status(400).send(HelperUtils.errorObj("Admin not found"));
        return;
    }

    if (req.body.fname && req.body.fname.length) {
        userObj.fname = req.body.fname
    }
    if (req.body.lname && req.body.lname.length) {
        userObj.lname = req.body.lname
    }
    if (req.body.email && req.body.email.length) {
        userObj.email = req.body.email
    }
    if (req.body.profileUrl && req.body.profileUrl.length) {
        userObj.profileUrl = req.body.profileUrl
    }
    if (req.body.username && req.body.username.length) {
        userObj.username = req.body.username
    }


    await userObj.save();

    res.status(200).send(HelperUtils.successObj("Profile Updated"));
    return;
});



/**
 * Delete Admin by id
 * @route DELETE /admin/{id}
 * @param {string} id.path.required - Admin Id
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return  Obj
 * @returns {Error}  Error - Unexpected error
 * @security Admin
 */

router.delete("/:id", [auth, adminAuth], async (req, res) => {

    const admin = await User.findById(req.params.id);
    if (!admin) {
        res.status(404).send(HelperUtils.errorObj("Admin Not Found"));
        return;
    }
    await admin.remove();

    res.send(HelperUtils.successObj("Admin Deleted"));
});




/**
 * @typedef UpdateProfile
 * @property {string} fname
 * @property {string} lname
 * @property {string} email
 * @property {string} profileUrl
 * @property {string} username
 */

/**
 * Update admin profile
 * @route POST /admin/profile/update
 * @param {UpdateProfile.model} UpdateProfile.body.required - admin login object
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Jwt Token in key result.token
 *      
 * @returns {Error}  Error - Unexpected error
 * @security Admin
 */


router.post("/profile/update", [auth, adminAuth], async (req, res) => {
    console.log(req.user)
    let userObj = await User.findById(req.user._id);
    if (!userObj) {
        res.status(400).send(HelperUtils.errorObj("Admin not found"));
        return;
    }

    if (req.body.fname && req.body.fname.length) {
        userObj.fname = req.body.fname
    }
    if (req.body.lname && req.body.lname.length) {
        userObj.lname = req.body.lname
    }
    if (req.body.email && req.body.email.length) {
        userObj.email = req.body.email
    }
    if (req.body.profileUrl && req.body.profileUrl.length) {
        userObj.profileUrl = req.body.profileUrl
    }
    userObj.username = req.body.username //* DMCN-765 Managers changing profile - user name field mandatory?
    // if (req.body.username && req.body.username.length) {
    //   userObj.username = req.body.username
    // }


    await userObj.save();

    res.status(200).send(HelperUtils.successObj("Profile Updated"));
    return;
});

/**
 * Admin Profile
 * @route GET /admin/profile
 * @group Admin - Admin operation
 * @returns {object} 200 -
 *      Return Admin Object with Profile
 *
 * @returns {Error}  Error - Unexpected error
 * @security Admin
 */

router.get("/profile", [auth, adminAuth], async (req, res) => {
    const profile = await User.findOne({ _id: req.user._id }).lean();
    if (!profile) {
        res.status(404).send(HelperUtils.errorObj("No profile found"));
        return;
    }
    let result = _.pick(profile, ["_id", "fname", "lname", "email", "profileUrl", "username"])
    if (!result.profileUrl) {
        result.profileUrl = PathUrlConstant.DEFAULT_USER_ICON
    }

    res.send(HelperUtils.successObj("Profile Updated", result));

});

/**
 * get all Admin Profile
 * @route GET /admin/list
 * @group Admin - Admin operation
 * @returns {object} 200 -
 *      Return Admin Object with Profile
 *
 * @returns {Error}  Error - Unexpected error
 * @security Admin
 */

router.get("/list", [auth, adminAuth], async (req, res) => {
    const adminList = await User.find({ role: UserRoleConstants.ADMIN }).select("fname lname email profileUrl username").lean();
    if (!adminList) {
        res.status(404).send(HelperUtils.errorObj("No admin found"));
        return;
    }


    res.send(HelperUtils.successObj("Retrieved Profile successfully", adminList));

});

/**
 * @typedef ForgotPassword
 * @property {string} email.required
 */


/**
 * Create forgot password request
 * @route POST /admin/password/forgot
 * @param {ForgotPassword.model} data.body.required - forgot password obj
 * @group Admin - Admin operation
 * @returns {object} 200 -
 *      Return Response
 * @security User
 * @returns {Error}  Error - Unexpected error
 */


router.post("/password/forgot", async (req, res) => {
    let forgot_password_host_link = config.get("CMS_HOST");
    //let forgot_password_host_link = config.get("CMS_HOST_ROLE");
    const user = await User.findOne({ email: req.body.email, role: { $in: [UserRoleConstants.ADMIN, UserRoleConstants.SUPER_ADMIN] } });
    if (!user) {
        res.status(404).send(HelperUtils.errorObj("Email Does Not Exist"));
        return;
    }
    user.resetPasswordToken = HelperUtils.generateUUID();
    user.resetPasswordExpires = Date.now() + 3600000;
    await user.save();
    // const resetUrl ="https://diamond-connect-cms.artoon.in/resetpassword/"+user.resetPasswordToken;
    // const resetUrl = `http://${req.headers.host}/resetpassword/${user.resetPasswordToken}`;
    const resetUrl = forgot_password_host_link + "resetpassword/" + user.resetPasswordToken;
    // const resetUrl = `http://${req.headers.host}/account/reset/${user.resetPasswordToken}`;
    // await mail.send({
    //   user,
    //   subject: 'Password reset mail',
    //   resetUrl,
    //   filename: 'password-reset'
    // })
    EmailController.sendEmailForForgotPassword({ email: req.body.email.toString(), first_name: user.fname, reset_password_link: resetUrl })
    let resetObj = {
        resetUrl: resetUrl,
        resetPasswordToken: user.resetPasswordToken
    }
    res.status(200).send(HelperUtils.successObj("Password Reset Emailed", resetObj));
    return;

});

/**
 * @typedef ResetPassword
 * @property {string} resetPasswordToken.required
 * @property {string} password.required
 */


/**
 * Set new password
 * @route POST /admin/password/reset
 * @param {ResetPassword.model} data.body.required - forgot password obj
 * @group Admin - Admin operation
 * @returns {object} 200 -
 *      Return Response
 * @security User
 * @returns {Error}  Error - Unexpected error
 */


router.post("/password/reset", async (req, res) => {
    const user = await User.findOne({
        resetPasswordToken: req.body.resetPasswordToken,
        resetPasswordExpires: { $gt: Date.now() }
    });
    if (!user) {
        res.status(404).send(HelperUtils.errorObj("Forgot Password Token Expired"));
        return;
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(req.body.password, salt);

    user.resetPasswordExpires = undefined;
    user.resetPasswordToken = undefined;
    const updatedUser = await user.save();

    res.status(200).send(HelperUtils.successObj("Password Reset"));
    return;
});

/**
 * @typedef  featurePermission
 * @property {string} title - name
 * @property {string} code  - uniquecode
 */

/**
* Add new features permission
* @route POST /admin/permission/add
* @param {featurePermission.model} data.body.required - permissionn details
* @group Admin - Admin operation
* @returns {object} 200 -
*      Return Response
* @returns {Error}  Error - Unexpected error
*/

router.post("/permission/add", [auth, adminAuth], async (req, res) => {
    try {
        // const code = req.body.code.replace(/\s/g, "").toUpperCase();
        const code = req.body.code
        const featureData = await AdminPermissionMaster.findOne({ $or: [{ title: req.body.title }, { 'code': code }] })
        if (featureData) {
            res.send(HelperUtils.errorObj("Code Already Exists", req.body));
            return
        }
        var query = { title: req.body.title, 'code': code };
        //if (req.body) {
        const newfeaturepermision = new AdminPermissionMaster(query);
        const addpermission = await newfeaturepermision.save();
        res.send(HelperUtils.successObj("Permission Added", addpermission))
        return
        // }
        //  else {
        //   res.send(HelperUtils.errorObj("please pass data to add"))
        // }
    } catch (error) {
        console.log(error)
        res.send(HelperUtils.errorObj("not added something went wrong", {}))
    }
})
/**
 * @typedef  editfeaturePermission
 * @property {string} permissionId - permision id
 * @property {string} title - name
 * @property {string} code  - uniquecode
 */

/**
* update features permission
* @route POST /admin/permission/edit
* @param {editfeaturePermission.model} data.body.required - permissionn details
* @group Admin - Admin operation
* @returns {object} 200 -
*      Return Response
* @security Admin
* @returns {Error}  Error - Unexpected error
*/

router.post("/permission/edit", [auth, adminAuth], async (req, res) => {
    try {
        var feature = await AdminPermissionMaster.findOne({ _id: req.body.permissionId });
        if (!feature) {
            res.send(HelperUtils.errorObj("feature not found please pass valid id", {}))
            return
        }
        else {
            // if (req.body.code) {
            //   const code = req.body.code.replace(/\s/g, "").toUpperCase();
            //   var permissionbycode = await AdminPermissionMaster.findOne({ 'code': code });
            //   if (permissionbycode._id.toString() != feature._id.toString() ) {
            //    // res.send(HelperUtils.errorObj("code already exists", {}));
            //   //  return
            //   }
            //   req.body.code = code;
            // }
            // var query = {
            //   _id: req.body.permissionId
            // }

            feature.title = req.body.title;
            await feature.save();
            //  const editfeature = await AdminPermissionMaster.findOneAndUpdate(query, { $set:obj },{new:true})
            res.send(HelperUtils.successObj("Updated", feature));
            return
        }
    } catch (error) {
        console.log(error);
        res.send(HelperUtils.errorObj("something wrong to update", {}))
    }
})
/**
 * @typedef  getfeatures
 * @property {string} search - name
 * @property {number} page  - page
 * @property {number} limit - limit
 */
/**
* get all features permission
* @route POST /admin/permission/list
* @param {featurePermission.model} data.body.required - permissionn details
* @group Admin - Admin operation
* @returns {object} 200 -
*      Return Response
* @security Admin
* @returns {Error}  Error - Unexpected error
*/
router.post("/permission/list", [auth, adminAuth], async (req, res) => {
    try {
        var page = 1;
        if (req.body.page) {
            page = req.body.page;
        }
        var limit = 10;
        if (req.body.limit) {
            limit = req.body.limit
        }
        searchQuery = {};
        if (req.body.search) {

            searchQuery['$or'] = [];
            searchQuery['$or'].push({ code: new RegExp(req.body.search.replace(/\s/g, "").toUpperCase(), 'i') });
            searchQuery['$or'].push({ title: new RegExp(req.body.search, 'i') });
        }
        var options = {
            page,
            limit
        }

        // var features = await AdminPermissionMaster.find({}).lean();
        var features = await AdminPermissionMaster.paginate(searchQuery, options)
        res.send(HelperUtils.successObj("Features Updated", features));
    } catch (error) {
        console.log(error);
        res.send(HelperUtils.errorObj("not such features list data found error", {}));
        return
    }
})
/**
* get a feature permission
* @route GET /admin/permission/{id}
* @param {string} id.path.required - id adminpermissionmaster id
* @group Admin - Admin operation
* @returns {object} 200 -
*      Return Response
* @security Admin
* @returns {Error}  Error - Unexpected error
*/
router.get("/permission/:id", [auth, adminAuth], async (req, res) => {
    try {
        var permissionobj = await AdminPermissionMaster.findById(req.params.id);
        if (!permissionobj) {
            res.send(HelperUtils.errorObj("not found", {}));
            return
        }
        res.send(HelperUtils.successObj("retrieve successfully", permissionobj));
        return
        //res.send(HelperUtils.successObj("features retrieve successfully", features));
    } catch (error) {
        console.log(error);
        res.send(HelperUtils.errorObj("not such features list data found error", {}));
        return
    }
})




// /**
//  * @typedef permissionsObj
//  * @property {string} permissions - permissions
//  */

/**
 * @typedef  AdminRolecreate 
 * @property {string}  title - name
 * @property {Array.<Object>} permissions
 */
/**
* Add Admin Role And its permission 
* @route POST /admin/rolemaster/create
* @param {AdminRolecreate.model} data.body.required - permissionn details
* @group Admin - Admin operation
* @returns {object} 200 -
*      Return Response
* @security Admin
* @returns {Error}  Error - Unexpected error
*/

router.post("/rolemaster/create", [auth, adminAuth], async (req, res) => {
    try {
        if (!req.body.title) {
            res.send(HelperUtils.errorObj("please pass admin title", {}))
        }

        const data = await AdminRoleMaster.findOne({ role: req.body.title });
        if (data) {
            res.send(HelperUtils.errorObj("Already Exists", {}));
            return
        }
        req.body.role = req.body.title
        let rolemaster = new AdminRoleMaster(req.body);
        await rolemaster.save();
        res.send(HelperUtils.successObj("successfully updated role master", rolemaster));

    } catch (error) {
        console.log(error);
        res.send(HelperUtils.errorObj("error goes ", {}));
        return

    }
})

/**
 * @typedef  getrolemasters
 * @property {string} search - name
 * @property {number} page  - page
 * @property {number} limit - limit
 */
/**
* get all admin role master with  permission
* @route POST /admin/rolemaster/list
* @param {getrolemasters.model} data.body.required - permissionn details
* @group Admin - Admin operation
* @returns {object} 200 -
*      Return Response
* @security Admin
* @returns {Error}  Error - Unexpected error
*/
router.post("/rolemaster/list", [auth, adminAuth], async (req, res) => {
    try {
        var page = 1;
        if (req.body.page) {
            page = req.body.page;
        }
        var limit = 10;
        if (req.body.limit) {
            limit = req.body.limit
        }
        searchQuery = {};
        if (req.body.search) {
            searchQuery['$or'] = [];
            //  searchQuery['$or'].push({ adminRole: new RegExp(req.body.search, 'i') });
            searchQuery['$or'].push({ title: new RegExp(req.body.search, 'i') });
        }
        var options = {
            populate: "permissions",
            page,
            limit
        }
        var allAdminRoles = await AdminRoleMaster.paginate(searchQuery, options)
        res.send(HelperUtils.successObj("Retrieved", allAdminRoles));
    } catch (error) {
        console.log(error);
        res.send(HelperUtils.errorObj("not such features list data found error", {}));
        return
    }
})
/**
* get a  AdminRolemaster 
* @route GET /admin/rolemaster/{id}
* @param {string} id.path.required - id adminpermissionmaster id
* @group Admin - Admin operation
* @returns {object} 200 -
*      Return Response
* @security Admin
* @returns {Error}  Error - Unexpected error
*/
router.get("/rolemaster/:id", [auth, adminAuth], async (req, res) => {
    try {
        var rolemasterObj = await AdminRoleMaster.findOne({ _id: req.params.id }).populate('permissions');
        if (!rolemasterObj) {
            res.send(HelperUtils.errorObj("not found", {}));
            return
        }
        res.send(HelperUtils.successObj("Retrieved", rolemasterObj));
        return
    } catch (error) {
        console.log(error);
        res.send(HelperUtils.errorObj("something went wrong"));
    }
})



/**
 * @typedef  AdminRole 
 * @property {string} adminroleMasterId - id
 * @property {string} title - role
 * @property {Array.<Object>} permissions
 */
/**
* update  Admin Role Ands its permission 
* add permissions to an existing role master 
* @route POST /admin/rolemaster/update
* @param {AdminRole.model} data.body.required - permissionn details
* @group Admin - Admin operation
* @returns {object} 200 -
*      Return Response
* @security Admin
* @returns {Error}  Error - Unexpected error
*/

router.post("/rolemaster/update", [auth, adminAuth], async (req, res) => {
    try {
        Adminid = req.body.adminroleMasterId;
        let adminObj = await AdminRoleMaster.findOne({ _id: Adminid }).lean();
        if (!adminObj) {
            res.send(HelperUtils.errorObj("no admin found"))
        }
        var title = adminObj.title;
        if (req.body.title) {
            title = req.body.title;
        }
        // find unique permissions from old and new req.body.peermisions;
        if (req.body.permissions) {
            // var permissionsIdArr = req.body.permissions
            // var arr = adminObj.permissions.map(x => x.toString());
            // arr = _.union(arr, permissionsIdArr);
            var arr = req.body.permissions
            //  console.log(arr);
        }
        else {
            var arr = adminObj.permissions
        }
        let adminRolemasterObj = await AdminRoleMaster.findOneAndUpdate({ _id: adminObj._id },
            {
                '$set':
                {
                    'title': title,
                    permissions: arr
                }
            }, { new: true });
        res.send(HelperUtils.successObj("Updated", adminRolemasterObj));
        return
    } catch (error) {
        console.log(error);
        res.send(HelperUtils.errorObj("something went wrong updating", {}));
        return
    }
})
/**
 * @typedef  AdminManage
 * @property {string} fname - first name
 * @property {string} lname - last name
 * @property {string}  email  - email
 * @property {string} phone - phone
 * @property {string} company  - company ID
 * @property {string} adminType - adminRoleMasterID
 * @property {string} adminmanage - internal/external 
 * @property {string} profileUrl  - profile url 
 * @property {string} password  - password
 * @property {boolean} ressetPassword - ressetPassword
 * @property {boolean} sendEmail - sendEmail
 */
/**
* create child Admin 
* @route POST /admin/adminmanage/create
* @param {AdminManage.model} data.body.required - permissionn details
* @group Admin - Admin operation
* @returns {object} 200 -
*      Return Response
* @security Admin
* @returns {Error}  Error - Unexpected error
*/
router.post("/adminmanage/create", [auth, adminAuth], async (req, res) => {

    try {

        let admin = await User.findOne({
            email: req.body.email.toLowerCase() /*, role: {
        $in: [UserRoleConstants.ADMIN, UserRoleConstants.SUPER_ADMIN, UserRoleConstants.DC_Admin,
        UserRoleConstants.Org_Admin, UserRoleConstants.Company_Admin, UserRoleConstants.Manager, UserRoleConstants.Site_Director

        ]
      }*/
        })
        if (admin) {
            res.status(400).send(HelperUtils.errorObj("Email Already Exists"));
            return;
        }
        if (req.body.phone) {
            var adminobj = await User.findOne({
                phone: req.body.phone, role: {
                    $in: [UserRoleConstants.ADMIN, UserRoleConstants.SUPER_ADMIN, UserRoleConstants.DC_Admin,
                    UserRoleConstants.Org_Admin, UserRoleConstants.Company_Admin, UserRoleConstants.Manager, UserRoleConstants.Site_Director]
                }
            })
            if (adminobj) {
                res.status(400).send(HelperUtils.errorObj("Phone Number Already Exists"));
                return;
            }
        }
        // var adminobj = await User.findOne({
        //   username: req.body.username, role: {
        //     $in: [UserRoleConstants.ADMIN, UserRoleConstants.SUPER_ADMIN, UserRoleConstants.DC_Admin,
        //     UserRoleConstants.Org_Admin, UserRoleConstants.Company_Admin, UserRoleConstants.Manager, UserRoleConstants.Site_Director]
        //   }
        // })
        // if (adminobj) {
        //   res.status(400).send(HelperUtils.errorObj("This username already used try new."));
        //   return;
        // }
        if (req.body.password && req.body.password.length != 0) {
            const salt = await bcrypt.genSalt(10);
            // req.body.password = pass_generator.generate({
            //   length: 8,
            //   numbers: true
            // });//"Diamond1#";
            var decryped_pass = req.body.password;
            req.body.password = await bcrypt.hash(req.body.password, salt);
        }
        else {
            //generate auto password
            const salt = await bcrypt.genSalt(10);
            req.body.password = pass_generator.generate({
                length: 8,
                numbers: true
            });//"Diamond1#";
            var decryped_pass = req.body.password;
            req.body.password = await bcrypt.hash(req.body.password, salt);
        }

        // let role = await AdminRoleMaster.find({ _id: req.body.adminType }).select('role')
        // console.log(role[0].role)
        var user = new User({
            fname: req.body.fname,
            lname: req.body.lname,
            email: req.body.email.toLowerCase(),
            password: req.body.password,
            pass: decryped_pass,
            //  phone: HelperUtils.generateRandomNumber(),
            //  username: req.body.username,
            role: UserRoleConstants.ADMIN
        });
        if (req.body.phone) {
            user.phone = req.body.phone
        }
        if (req.body.profileUrl && req.body.profileUrl.length) {
            user.profileUrl = req.body.profileUrl
        }
        else { // set default company logo on profile
            if (req.body.company) {
                let companyobj = await Company.findById(req.body.company).populate({ path: "companyLogo", select: "filePath" });
                if (companyobj && companyobj.companyLogo.length) {
                    let companylogo = companyobj.companyLogo[0].filePath;
                    user.profileUrl = companylogo;
                }

            }
        }
        await user.save();
        let regOObj = new Registration({
            user: user._id,
            role: user.role,
            isCompleted: true
        })

        await regOObj.save();
        user.profile = regOObj._id;
        await user.save()
        //same company's admin automatic follows each other
        if (req.body.company) {
            let alladminsIdArr = await AdminManage.distinct("user", { company: req.body.company, isDel: { $in: [false, null] } });
            await User.updateOne({ _id: user._id }, { $push: { following: alladminsIdArr, followers: alladminsIdArr } });
            for (let i = 0; i < alladminsIdArr.length; i++) {
                await User.updateOne({ _id: alladminsIdArr[i] }, { $push: { following: user._id, followers: user._id } })
            }
        }

        // console.log("--create-->>", req.body);  
        const createdBY = await AdminManage.find({ user: req.user._id }).populate({ path: 'adminType', select: 'title' })
        var adminmanageObj = new AdminManage({
            user: user._id,
            adminmanage: req.body.adminmanage,
            company: req.body.company,
            adminType: req.body.adminType,
            createdByUser: req.user._id,
            ressetPassword: req.body.ressetPassword
        })
        // if(req.body.company && req.body.company.length){
        //   adminmanageObj.company = req.body.company
        // }
        if (req.body.college) adminmanageObj.college = req.body.college
        await adminmanageObj.save();
        // adminmanageObj[password] = decryped_pass;
        if (req.body.sendEmail) {
            EmailController.sendEmailForSubAdminCreation({ email: req.body.email.toLowerCase(), password: decryped_pass })
        }

        let adminRole = await AdminRoleMaster.findOne({ _id: req.body.adminType })
        let allow = false
        if (adminRole && adminRole.role != UserRoleConstants.BC_INTERN) allow = true   // check user not a intern role
        // add admin to all event groups
        let events = await Event.distinct('_id', adminmanageObj.company ? { companies: adminmanageObj.company } : {})
        for (let j = 0; j < events.length; j++) {
            let groupObj = await Group.find({ event: events[j] }).lean()
            if (groupObj && allow) {
                for (let k = 0; k < groupObj.length; k++) {
                    await groupHandler.addSubscriberInGroup(groupObj[k].createdBy, [adminmanageObj.user], groupObj[k]._id, ChatEventConstant.GROUP_ADMIN)
                }
            }
        }

        res.status(200).send(HelperUtils.successObj("Created", adminmanageObj));
        return;
    } catch (error) {
        console.log(error);
        res.send(HelperUtils.errorObj("something went wrong", {}));
    }
});


/**
 * @typedef AdminManageSearch
 * @property {number} page - page
 * @property {string} adminmanage - send type Internal/External 
 * @property {string} search - search by inter/external 
 * @property {string} company - companyID
 * @property {string} adminType - adminType / admin role
 */

/**
* get list of child admin search by internal / external
* @route POST /admin/adminmanage/list
* @param {AdminManageSearch.model} data.body.required - search
* @group Admin - Admin operation
* @returns {object} 200 -
*      Return Response
* @security Admin
* @returns {Error}  Error - Unexpected error
*/
router.post("/adminmanage/list", [auth, adminAuth], async (req, res) => {
    try {
        var page = 1;
        if (req.body.page) {
            page = req.body.page
        }
        var limit = 10;
        if (req.body.limit) {
            limit = req.body.limit
        }
        var query = {};
        query["$and"] = [];
        query["$and"].push({ adminmanage: req.body.adminmanage });
        query["$and"].push({ isDel: { $in: [false, null] } })

        if (req.body.company) {
            query["$and"].push({ company: req.body.company })
        }
        if (req.body.adminType) {
            query["$and"].push({ adminType: req.body.adminType })
        }

        // const currentUser = await AdminManage.find({createdByUser:req.user._id}).select('user')
        if (req.user.role != "Super Admin") {
            var finalArr = [];
            const childUserIdArr = await AdminManage.distinct('user', { createdByUser: req.user._id })
            let adminArr = [];
            if (childUserIdArr && childUserIdArr.length) {
                childUserIdArr.forEach(id => {
                    finalArr.push(id);
                })
                adminArr = await getChildUser(childUserIdArr[0], finalArr)

            }
            query["$and"].push({ user: { '$in': finalArr } })
            console.log({ user: { '$in': finalArr } })
        }
        if (req.body.search) {
            var userQueryOr = {};
            userQueryOr["$or"] = [];
            userQueryOr["$or"].push({ fname: new RegExp(req.body.search, 'i') });
            userQueryOr["$or"].push({ lname: new RegExp(req.body.search, 'i') });
            userQueryOr["$or"].push({ username: new RegExp(req.body.search, 'i') });
            userQueryOr["$or"].push({ email: new RegExp(req.body.search, 'i') });
            var fullNameArr = req.body.search.split(" ")
            if (fullNameArr && fullNameArr[1]) {
                userQueryOr["$or"].push({ fname: new RegExp(fullNameArr[0], 'i'), lname: new RegExp(fullNameArr[1], 'i') });
            }
            var userIdArr = await User.distinct("_id", userQueryOr);

            if (userIdArr && userIdArr.length) {
                query["$and"].push({ user: { $in: userIdArr } })
            }
            else {
                let obj = {
                    docs: [],
                    limit: 10,
                    total: 1,
                    pages: 1,
                    page: 1
                }
                res.send(HelperUtils.successObj("retrieve list successfully", obj));
                return;
            }
        }
        var options = {
            populate: [
                { path: 'adminType', select: 'title role', populate: [{ path: 'permissions', select: 'title code' }] },
                { path: 'user', select: 'fname lname email phone profileUrl' },
                { path: 'company', select: 'name email' },
                { path: 'createdByUser', select: 'fname lname role' }

            ],
            sort: ({ createdAt: -1 }),
            page,
            limit
        }


        var adminlistObj = await AdminManage.paginate(query, options)


        res.send(HelperUtils.successObj("retrieve list successfully", adminlistObj));
        return;
    } catch (error) {
        console.log(error);
        res.send(HelperUtils.errorObj("something went wrong", {}));
    }
})

/**
 * @typedef UpdateAdminManage
 * @property {string} adminId
 * @property {string} fname
 * @property {string} lname
 * @property {string} email
 * @property {string} profileUrl
 * @property {string} username
 * @property {string} company
 * @property {string} adminType
 */

/**
 * Admin User update
 * @route POST /admin/adminmanage/update
 * @param {UpdateAdminManage.model} UpdateAdminManage.body.required - admin update object
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return admin obj
 * @returns {Error}  Error - Unexpected error
 * @security Admin
 */


router.post("/adminmanage/update", [auth, adminAuth], async (req, res) => {
    try {
        let adminObj = await AdminManage.findById(req.body.adminId);

        if (!adminObj) {
            res.status(400).send(HelperUtils.errorObj("Admin not found"));
            return;
        }

        let userObj = await User.findById(adminObj.user);

        if (req.body.fname && req.body.fname.length) {
            userObj.fname = req.body.fname
        }
        if (req.body.lname && req.body.lname.length) {
            userObj.lname = req.body.lname
        }
        if (req.body.email && req.body.email.length) {
            userObj.email = req.body.email
        }
        if (req.body.profileUrl && req.body.profileUrl.length) {
            userObj.profileUrl = req.body.profileUrl
        }
        if (req.body.phone && req.body.phone.length) {
            userObj.phone = req.body.phone
        }
        // if (req.body.username && req.body.username.length) {
        //   userObj.username = req.body.username
        // }

        if (req.body.company && req.body.company.length) {
            if (adminObj.company.toString() != req.body.body) {
                console.log("===========");
                let alluser = await AdminManage.distinct("user", { company: adminObj.company, isDel: { $in: [false, null] } })
                //remove from folowers or follwing
                await User.updateMany({ _id: { $in: alluser }, followers: adminObj.user }, { $pull: { followers: adminObj.user } });
                await User.updateMany({ _id: { $in: alluser }, following: adminObj.user }, { $pull: { following: adminObj.user } })

                let newuser = await AdminManage.distinct("user", { company: req.body.company, isDel: { $in: [false, null] } });
                await User.updateMany({ _id: { $in: newuser } }, { $push: { following: adminObj.user, followers: adminObj.user } })
                await User.findOneAndUpdate({ _id: adminObj.user }, { $set: { followers: newuser, following: newuser } })
            }// else {
            //   let alluser = await AdminManage.distinct("user", { company: req.body.company })
            //   //remove from folowers or follwing
            //   // await User.updateMany({ _id: { $in: alluser }, followers: adminObj.user }, { $pull: { followers: adminobj.user } });
            //   await User.updateMany({ _id: { $in: alluser } }, { $push: { following: adminObj.user, followers: adminObj.user } })
            //   await User.findOneAndUpdate({ _id: adminObj.user }, { $set: { followers: alluser, following: alluser } })
            // }
            adminObj.company = req.body.company;
            await adminObj.save();
        }
        if (req.body.college) adminObj.college = req.body.college

        if (req.body.adminType && req.body.adminType.length) {
            adminObj.adminType = req.body.adminType;
            await adminObj.save();
        }

        await userObj.save();
        var updateAdminObj = await AdminManage.findById(adminObj._id)
            .populate({ path: 'user', select: 'fname lname email phone profileUrl' })
            .populate({ path: 'company', select: 'name email' })
            .populate({ path: 'adminType', select: 'title role', populate: [{ path: 'permissions', select: 'title code' }] },)
            .populate({ path: "college", populate: { path: "image", select: "filePath" } })
        res.status(200).send(HelperUtils.successObj("Profile Updated", updateAdminObj));
        return
    } catch (error) {
        console.log(error);
        res.send(HelperUtils.errorObj("something went wrong", {}));
        return
    }
});


/**
 * Delete Admin by id
 * @route DELETE /admin/adminmanage/{id}
 * @param {string} id.path.required - Admin Id
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return  Obj
 * @returns {Error}  Error - Unexpected error
 * @security Admin
 */

router.delete("/adminmanage/:id", [auth, adminAuth], async (req, res) => {
    try {
        const adminmanageObj = await AdminManage.findById(req.params.id)
        if (!adminmanageObj) {
            res.send(HelperUtils.errorObj("Admin not found"));
            return
        }
        // const user = await User.findById(adminmanageObj.user);
        // let userId = user._id
        // await Registration.deleteOne({ user: userId });
        // await User.updateMany({ followers: userId }, { $pull: { followers: userId } })
        // await User.updateMany({ following: userId }, { $pull: { following: userId } })
        // await adminmanageObj.remove();
        // await user.remove();

        // now only soft deleting user
        await User.findOneAndUpdate({ _id: adminmanageObj.user }, { $set: { isDel: true } })
        await AdminManage.findOneAndUpdate({ _id: req.params.id }, { $set: { isDel: true } })

        // remove admin from all event groups
        let gIds = await GroupSubscriber.distinct('gId', { mId: adminmanageObj.user })
        if (gIds && gIds.length) {
            for (let i = 0; i < gIds.length; i++) {
                let groupObj = await Group.findOne({ _id: gIds[i] })
                await groupHandler.removeMemberFromGroup(groupObj.createdBy, adminmanageObj.user, gIds[i])
            }
            // await removeMemberFromGroup(groupObj.createdBy, adminmanageObj._id, groupId)
            // await groupHandler.addSubscriberInGroup(groupObj.createdBy, [adminmanageObj._id], groupObj._id)
        }

        res.send(HelperUtils.successObj("Admin Deleted"));
        return
    } catch (error) {
        console.log(error);
        res.send(HelperUtils.errorObj("something went wrong", {}));
        return
    }
});
/**
 * Get Admin by id
 * @route GET /admin/adminmanage/{id}
 * @param {string} id.path.required - Admin Id
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return  Obj
 * @returns {Error}  Error - Unexpected error
 * @security Admin
 */
router.get("/adminmanage/:id", [auth, adminAuth], async (req, res) => {
    try {
        const adminmanageObj = await (await AdminManage.findById(req.params.id));
        if (!adminmanageObj) {
            res.send(HelperUtils.errorObj("admin user not found", {}));
            return
        }

        let userObj = await AdminManage.findById(adminmanageObj._id)
            .populate({ path: 'user', select: 'fname lname email phone profileUrl' })
            .populate({ path: 'company', select: 'name email' })
            .populate({ path: 'adminType', select: 'title role', populate: [{ path: 'permissions', select: 'title code' }] })
            .populate({ path: "college", populate: { path: "image", select: "filePath" } })
        res.send(HelperUtils.successObj("successfully retrieve ", userObj));
        return
    } catch (error) {
        console.log(error);
        res.send(HelperUtils.errorObj("something went wrong", {}));
        return;
    }
})

/**
 * @typedef UserPasswordReset
 * @property {string} email.required
 * @property {string} newpassword.required
 * @property {string} conpassword.required
 */

/**
 * Admin Login
 * @route POST /admin/user/password/resset
 * @param {UserPasswordReset.model} AdminPasswordReset.body.required - admin login object
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Jwt Token in key result.token
 * @security Admin  
 * @returns {Error}  Error - Unexpected error
 */


router.post("/user/password/resset", [auth, adminAuth], async (req, res) => {
    try {
        let userObj = await User.findOne({ email: req.body.email.toLowerCase(), role: { $in: [UserRoleConstants.PLAYER, UserRoleConstants.COACH, UserRoleConstants.FAN, UserRoleConstants.PARENT] } });
        if (!userObj && userObj.length == 0) {
            res.send(HelperUtils.errorObj("User Not Found"));
            return
        }

        const salt = await bcrypt.genSalt(10);
        userObj.password = await bcrypt.hash(req.body.newpassword, salt)

        await userObj.save()
        let sendemail = await EmailController.ressetpasswordUser(userObj._id, req.body.newpassword)
        if (sendemail == true) {
            res.send(HelperUtils.successObj("Password Reset and Email Sent", {}));
            return
        }
        else {
            res.send(HelperUtils.errorObj("something went wrong"));
            return
        }
    } catch (error) {
        console.log(error)
        res.send(HelperUtils.errorObj("something went wrong"))
    }
})
/**
* @typedef AddressModel
* @property {string} city - city
* @property {string} state - state
* @property {string} zipcode - zipcode
*/

/**
* @typedef BCCUserBasicEdit
* @property {string} userId - Id of user
* @property {string} fname - fname of user
* @property {string} lname - lname of user
* @property {string} dob - dob of user
* @property {string} phone - phone of user
* @property {string} cCode - cCode of user
* @property {string} profilePic - profilePic ID
* @property {string} bio - bio
* @property {string} game-type - "game-type"
* @property {AddressModel.model} address - address
*/

/**
 * edit basic detail of coach
 * @route POST /admin/user/profile/edit
 * @group Admin - Admin operation
 * @param {BCCUserBasicEdit.model} data.body.required - basic detail edit coach
 * @returns {object} 200 - 
 *      Return Registartion Object
 *      
 * @returns {Error}  Error - Unexpected error
 * @security Admin
 */

router.post("/user/profile/edit", [auth, adminAuth], async (req, res) => {
    try {
        let userObj = await User.find({ _id: req.body.userId })
        userObj = userObj[0]

        var fields = req.body;
        delete fields.userId
        if (fields.email) {
            let checkEmail = await User.find({ email: fields.email.toLowerCase(), '_id': { '$ne': userObj._id }, role: { $in: ['Coach', 'Player', 'Fan'] } })
            if (checkEmail && checkEmail.length) {
                res.send(HelperUtils.errorObj("Email Already Exists"));
                return
            }
        }
        if (fields.phone && fields.phone != userObj.phone) {
            let checkPhone = await User.find({ phone: fields.phone, '_id': { '$ne': userObj._id }, role: { $in: ['Coach', 'Player', 'Fan'] } })
            if (checkPhone && checkPhone.length) {
                res.send(HelperUtils.errorObj("Phone Number Already Exists"));
                return
            }
        }
        var imageObj;

        if (fields.profilePic) {

            //imageObj = await FileUpload.findById(fields.profilePic)
            imageObj = await FileUpload.find({ filePath: fields.profilePic })
            if (imageObj && imageObj.length) {
                imageObj = imageObj[0]
                fields.profileUrl = imageObj.filePath

            }
        }
        else {
            delete fields.profilePic
        }
        var profileField = _.pick(fields, ["dob", "address", "bio", , "game-type"]);

        profileField.profilePic = imageObj._id;

        if (profileField) {
            let query = {
                "user": userObj._id
            }
            if (profileField.dob) {
                // profileField.isImport = 2;
            }
            await Registration.findOneAndUpdate(query, { $set: profileField });
        }

        var userField = _.pick(fields, ["fname", "lname", "phone", "cCode"])

        if (userField) {
            userField.profileUrl = fields.profilePic
            let query = {
                _id: userObj._id
            }
            await User.findOneAndUpdate(query, { $set: userField })
        }
        res.send(HelperUtils.successObj("Profile Updated"));
        return

    } catch (error) {
        console.log(error)
        res.send(HelperUtils.errorObj("something went wrong"))
        return
    }
})
/**
* @typedef SocialLinkModel
* @property {string} insta - instagram
* @property {string} twt - twitter
*/

/**
* @typedef TeamBasicEdit
* @property {string} name - name of team
* @property {string} teamLogo - Id of team image
* @property {string} description - information
* @property {string} teamRecord - team Record with opponent
* @property {SocialLinkModel.model} social_link - link of Instegram and Twitter
* @property {string} div - division
* @property {string} ageGroup - agergroup
* @property {string} shoplink - shop store link
*/

/**
 * Edit Team Basic 
 * @route POST /admin/team/edit/{id}
 * @param {string} id.path.required - Team ID
 * @param {TeamBasicEdit.model} TeamBasicEdit.body - admin login object
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Jwt Token in key result.token
 * @security Admin  
 * @returns {Error}  Error - Unexpected error
 */


router.post("/team/edit/:id", [auth, adminAuth], async (req, res) => {
    try {
        var fields = req.body;

        let teamObj = await Team.findById(req.params.id)
        console.log(teamObj)
        let teamfeilds = _.pick(fields, ['teamRecord', 'ageGroup', 'div']);
        let parentTeamFeilds = _.pick(fields, ['name', 'description', 'social-link', 'shoplink', 'teamLogo']);

        if (teamfeilds) {
            let query = {
                _id: teamObj._id
            }
            await Team.findOneAndUpdate(query, { $set: teamfeilds })
        }
        if (parentTeamFeilds) {
            let query = {
                _id: teamObj.parentTeam
            }
            await ParentTeam.findOneAndUpdate(query, { $set: parentTeamFeilds })
        }
        console.log(teamfeilds);
        console.log(parentTeamFeilds)
        res.send(HelperUtils.successObj("Team Updated"));
        return
    } catch (error) {
        console.log(error);
        res.send(HelperUtils.errorObj("something went wrong"));
        return
    }

})

/**
 * Get One Team Information
 * @route GET /admin/team/{id}
 * @param {string} id.path.required Team Id
 * @group Admin - User operation for Report
 * @returns {object} 200 -
 *      Return Response
 * @security User
 * @security Admin
 * @returns {Error}  Error - Unexpected error
 */


router.get("/team/:id", async (req, res) => {
    try {

        let parentTeamObj = await ParentTeam.findOne({ _id: req.params.id }).lean()
        var team = await Team.findOne({ isHold: false, parentTeam: parentTeamObj, coach: parentTeamObj.coach }).populate('coach', 'fname lname profileUrl').populate('div', 'title')
            .populate({ path: 'parentTeam', select: 'name description social-link followers following shoplink', populate: { path: 'teamLogo', select: 'filePath' } }).sort({ "createdAt": -1 }).lean();


        delete team.parentTeam._id;
        team = { ...team, ...team.parentTeam }
        delete team.parentTeam;
        team.coachName = "";
        if (team.coach && team.coach.fname) {
            team.coachName = team.coach.fname + " " + team.coach.lname;
        }
        if (!team['social-link']) {
            team['social-link'] = {
                "twt": "",
                "insta": ""
            }
        }
        if (team['social-link'] && !team['social-link'].twt) {
            team['social-link'].twt = ""
        }
        if (team['social-link'] && !team['social-link'].insta) {
            team['social-link'].insta = ""
        }
        team.followers = team.followers.length;
        team.following = team.following.length;

        res.send(HelperUtils.successObj("team Retrieved sucessfully", team));

    } catch (error) {
        console.log(error);
        res.send(HelperUtils.errorObj("something went wrong"))
        return
    }
});

/**
 * @typedef AdminLogin
 * @property {string} email.required
 * @property {string} password.required
 */

/**
 * Admin Login
 * @route POST /admin/adminmange/login
 * @param {AdminLogin.model} AdminLogin.body.required - admin login object
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Jwt Token in key result.token
 *      
 * @returns {Error}  Error - Unexpected error
 */


router.post("/adminmange/login", async (req, res) => {
    try {
        const { error } = validateLogin(req.body);
        if (error) {
            res.status(400).send(HelperUtils.errorObj(error.details[0].message));
            return;
        }
        var user = await User.findOne({
            $and: [{ $or: [{ email: req.body.email.toLowerCase() }, { username: req.body.email.toLowerCase() }] },
            {
                role: {
                    $in: [UserRoleConstants.ADMIN, UserRoleConstants.SUPER_ADMIN]
                }
            }]
        });
        if (!user) {
            res.status(400).send(HelperUtils.errorObj("Invalid Email or Password"));
            return;
        }
        var adminROle = [UserRoleConstants.SUPER_ADMIN, UserRoleConstants.ADMIN];
        if (user && user.role && !adminROle.includes(user.role)) {
            res.status(400).send(HelperUtils.errorObj("InValid Role"));
            return;
        }


        const isValid = await bcrypt.compare(req.body.password, user.password);
        if (req.body.password) {  //remove master pwd DMCN 630
            if (!isValid) {
                res.status(400).send(HelperUtils.errorObj("Invalid Email or password"));
                return;
            }
        }
        if (user.isDel == true) {
            res.send(HelperUtils.errorObj("user not active"));
            return
        }

        var AdminObj = await AdminManage.findOne({ user: user._id }).populate([
            { path: 'adminType', select: 'title role', populate: [{ path: 'permissions', select: 'title code' }] },
            { path: 'user', select: 'fname lname email username profileUrl' },
            { path: 'company', select: 'name email' }
        ]).lean()
        if (AdminObj && AdminObj.adminType && AdminObj.adminType.role == UserRoleConstants.Site_Director) {
            res.send(HelperUtils.errorObj("Site Director Can't login"));
            return
        }
        // AdminObj = AdminObj.toObject();
        if (AdminObj != null) {
            if (AdminObj.ressetPassword) {
                AdminObj.ressetPassword = AdminObj.ressetPassword
            }
            else {
                AdminObj.ressetPassword = false
            }
        }
        if (AdminObj && AdminObj.adminmanage.toLowerCase() == "internal") {
            var ressetPwd = AdminObj.ressetPassword     // get reset password for below use when admin is Internal DC Admin
        }
        if (AdminObj && AdminObj.adminmanage.toLowerCase() == "external") {
            userPermissions = AdminObj.adminType.permissions
            var permObj = {};
            for (let i = 0; i < PermissionsCodesConstant.length; i++) {
                var flag
                for (let j = 0; j < userPermissions.length; j++) {
                    if (PermissionsCodesConstant[i] === userPermissions[j].code) {
                        flag = true
                        break;
                    }
                    else {
                        flag = false
                    }
                }
                if (flag && flag == true) {

                    let permission = {
                        name: PermissionsKeysConstant[PermissionsCodesConstant[i]],
                        code: PermissionsCodesConstant[i],
                        flag: true
                    }
                    // let permission = PermissionsKeysConstant[PermissionsCodesConstant[i]]
                    // let x = {}
                    permObj[PermissionsCodesConstant[i]] = permission
                    // permArr.push(x)

                }
                else {
                    let permission = {
                        name: PermissionsKeysConstant[PermissionsCodesConstant[i]],
                        code: PermissionsCodesConstant[i],
                        flag: false
                    }
                    // let permission = PermissionsKeysConstant[PermissionsCodesConstant[i]]
                    // let x = {}
                    permObj[PermissionsCodesConstant[i]] = permission
                    // permArr.push(x)
                }
            }
            let companyList = [];
            let Userobj = {}
            companyList.push(AdminObj.company)
            let auth = await user.generateAuthToken()
            Userobj['user'] = AdminObj.user;
            Userobj['adminType'] = AdminObj.adminType.role;
            Userobj['company'] = companyList;
            Userobj['permissions'] = permObj;
            Userobj['token'] = auth.token;
            Userobj['role'] = auth.role;
            Userobj['ressetPassword'] = AdminObj.ressetPassword
            //  Userobj['authDetails'] =  await user.generateAuthToken()
            // res.send(HelperUtils.successObj("Login Successfully!", await user.generateAuthToken()));
            res.send(HelperUtils.successObj("Logged In", Userobj))
            return
        }

        else {
            let permObj = {}
            for (let i = 0; i < PermissionsCodesConstant.length; i++) {
                let permission = {
                    name: PermissionsKeysConstant[PermissionsCodesConstant[i]],
                    code: PermissionsCodesConstant[i],
                    flag: true
                }
                // let permission = PermissionsKeysConstant[PermissionsCodesConstant[i]]
                // let x = {}
                permObj[PermissionsCodesConstant[i]] = permission
            }
            let companyObj = await Company.find({}).select('name email')
            let Userobj = {}
            let auth = await user.generateAuthToken()
            Userobj['user'] = user._id;
            Userobj['company'] = companyObj;
            Userobj['permissions'] = permObj;
            Userobj['token'] = auth.token;
            Userobj['role'] = auth.role;
            if (auth.role != "Super Admin") {  // check admin is DC Admin and set properties
                Userobj['adminType'] = AdminObj.adminType.role;
                Userobj['ressetPassword'] = ressetPwd

            }
            // set role for super Admin
            else {
                Userobj['adminType'] = user.role;
                Userobj['ressetPassword'] = false;
            }

            res.send(HelperUtils.successObj("Logged In", Userobj));
            return
        }
    }
    catch (error) {
        console.log(error)
    }
});
/**
 * @typedef AdminPasswordReset
 * @property {string} currentpassword.required
 * @property {string} newpassword.required
 * @property {string} conpassword.required
 */

/**
 * Admin password resset when first login
 * @route POST /admin/adminmanage/ressetpassword
 * @param {AdminPasswordReset.model} AdminPasswordReset.body.required - admin login object
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Jwt Token in key result.token
 * @security Admin  
 * @returns {Error}  Error - Unexpected error
 */

router.post("/adminmanage/ressetpassword", [auth, adminAuth], async (req, res) => {
    try {
        if (req.body.newpassword != req.body.conpassword) {
            res.send(HelperUtils.errorObj("Passwords Do Not Match"));
            return
        }
        let currentpwd = req.body.currentpassword;
        let userObj = await User.findOne({ _id: req.user._id })
        if (!userObj) {
            res.send(HelperUtils.errorObj("user not found"));
            return
        }
        const isValid = await bcrypt.compare(currentpwd, userObj.password);
        console.log(isValid)
        if (!isValid) {
            res.send(HelperUtils.errorObj("Incorrect Password"));
            return
        }
        const salt = await bcrypt.genSalt(10);
        userObj.password = await bcrypt.hash(req.body.newpassword, salt)
        userObj.pass = req.body.newpassword
        await userObj.save()
        let adminObj = await AdminManage.findOne({ user: userObj._id });
        adminObj.ressetPassword = false;
        await adminObj.save();
        console.log(adminObj)
        res.send(HelperUtils.successObj("Password Updated", userObj))

    } catch (error) {
        console.log(error)
        res.send(HelperUtils.errorObj("something went wrong"));
        return
    }
})

/**
 * @typedef TestLogin
 * @property {string} email.required
 * @property {string} password.required
 */

/**
 * Admin Login
 * @route POST /admin/login/test
 * @param {TestLogin.model} TestLogin.body.required - admin login object
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Jwt Token in key result.token
 *      
 * @returns {Error}  Error - Unexpected error
 */
router.post("/login/test", async (req, res) => {
    const { error } = validateLogin(req.body);
    if (error) {
        res.status(400).send(HelperUtils.errorObj(error.details[0].message));
        return;
    }
    let user = await User.findOne({
        $and: [{ $or: [{ email: req.body.email.toLowerCase() }, { username: req.body.email.toLowerCase() }] },
        { role: { $in: [UserRoleConstants.ADMIN, UserRoleConstants.SUPER_ADMIN] } }]
    });
    if (!user) {
        res.status(400).send(HelperUtils.errorObj("Invalid Email or password"));
        return;
    }
    var adminROle = [UserRoleConstants.SUPER_ADMIN, UserRoleConstants.ADMIN];
    if (user && user.role && !adminROle.includes(user.role)) {
        res.status(400).send(HelperUtils.errorObj("InValid Role"));
        return;
    }


    const isValid = await bcrypt.compare(req.body.password, user.password);
    if (!isValid) {
        res.status(400).send(HelperUtils.errorObj("Invalid Email or password"));
        return;
    }

    res.send(HelperUtils.successObj("Login Successfully!", await user.generateAuthToken()));
});
/**
 * Get Permission list By admin  Role
 * @route Get /admin/permission/list/rolewise
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Jwt Token in key result.token
 * @security Admin   
 * @returns {Error}  Error - Unexpected error
 */
router.get("/permission/list/rolewise", auth, async (req, res) => {
    try {
        var AdminObj = await AdminManage.findOne({ user: req.user._id }).populate([
            { path: 'adminType', select: 'title role', populate: [{ path: 'permissions', select: 'title code' }] },
            { path: 'user', select: 'fname lname email username profileUrl' },
            { path: 'company', select: 'name email' }
        ]).lean();
        if (AdminObj && AdminObj.adminmanage.toLowerCase() == "external") {
            userPermissions = AdminObj.adminType.permissions
            var permObj = {};
            for (let i = 0; i < PermissionsCodesConstant.length; i++) {
                var flag
                for (let j = 0; j < userPermissions.length; j++) {
                    if (PermissionsCodesConstant[i] === userPermissions[j].code) {
                        flag = true
                        break;
                    }
                    else {
                        flag = false
                    }
                }
                if (flag && flag == true) {

                    let permission = {
                        name: PermissionsKeysConstant[PermissionsCodesConstant[i]],
                        code: PermissionsCodesConstant[i],
                        flag: true
                    }
                    permObj[PermissionsCodesConstant[i]] = permission

                }
                else {
                    let permission = {
                        name: PermissionsKeysConstant[PermissionsCodesConstant[i]],
                        code: PermissionsCodesConstant[i],
                        flag: false
                    }
                    permObj[PermissionsCodesConstant[i]] = permission
                }
            }
            if (AdminObj && AdminObj.company && AdminObj.company.name.includes("Prospect Wire")) {
                permObj['10064'] = {
                    name: "Team Player Ranking",
                    code: 1064,
                    flag: true
                }
            } else {
                permObj['10064'] = {
                    name: "Team Player Ranking",
                    code: 1064,
                    flag: false
                }
            }
            let companyList = [];
            let Userobj = {}
            companyList.push(AdminObj.company)
            Userobj['user'] = req.user._id;
            Userobj['company'] = companyList;
            Userobj['permissions'] = permObj;
            res.send(HelperUtils.successObj("permissions list retrieved successfully", Userobj))
            return
        } else if (AdminObj && AdminObj.adminmanage.toLowerCase() == "internal") {
            userPermissions = AdminObj.adminType.permissions
            var permObj = {};
            for (let i = 0; i < PermissionsCodesConstant.length; i++) {
                var flag
                for (let j = 0; j < userPermissions.length; j++) {
                    if (PermissionsCodesConstant[i] === userPermissions[j].code) {
                        flag = true
                        break;
                    }
                    else {
                        flag = false
                    }
                }
                if (flag && flag == true) {

                    let permission = {
                        name: PermissionsKeysConstant[PermissionsCodesConstant[i]],
                        code: PermissionsCodesConstant[i],
                        flag: true
                    }
                    permObj[PermissionsCodesConstant[i]] = permission

                }
                else {
                    let permission = {
                        name: PermissionsKeysConstant[PermissionsCodesConstant[i]],
                        code: PermissionsCodesConstant[i],
                        flag: false
                    }
                    permObj[PermissionsCodesConstant[i]] = permission
                }
            }
            // static team player ranking permission access for temporary
            permObj['10064'] = {
                name: "Team Player Ranking",
                code: 1064,
                flag: true
            }
            let companyList
            let Userobj = {}
            companyList = await Company.find({}).sort({ name: -1 }).select('name email')
            Userobj['user'] = req.user._id;
            Userobj['company'] = companyList;
            Userobj['permissions'] = permObj;
            res.send(HelperUtils.successObj("permissions list retrieved successfully", Userobj))
            return
        } else {
            let permObj = {}
            for (let i = 0; i < PermissionsCodesConstant.length; i++) {
                let permission = {
                    name: PermissionsKeysConstant[PermissionsCodesConstant[i]],
                    code: PermissionsCodesConstant[i],
                    flag: true
                }
                permObj[PermissionsCodesConstant[i]] = permission
            }
            // static team player ranking permission access for temporary
            permObj['10064'] = {
                name: "Team Player Ranking",
                code: 1064,
                flag: true
            }
            let companyObj = await Company.find({}).sort({ name: -1 }).select('name email')
            let Userobj = {}

            Userobj['user'] = req.user._id;
            Userobj['company'] = companyObj;
            Userobj['permissions'] = permObj;
            res.send(HelperUtils.successObj("permissions list retrieved successfully", Userobj));
            return
        }

    }
    catch (ex) {
        res.send(HelperUtils.errorObj("Something wrong"))
        return
    }
});

/**
* @typedef DataToolInputNumberFilter
* @property {string} case
* @property {number} value
*/
/**
* @typedef DataToolInputStringFilter
* @property {string} case
* @property {string} value
*/
/**
 * @typedef DataToolInputData
 * @property {string} dateFrom
 * @property {string} dateTo
 * @property {string} deviceType
 * @property {string} gameType
 * @property {string} event_type
 * @property {string} TeamId
 * @property {DataToolInputStringFilter.model} pitch_type
 * @property {DataToolInputStringFilter.model} pitcher_team
 * @property {DataToolInputStringFilter.model} batter_team
 * @property {DataToolInputStringFilter.model} pitcher_name
 * @property {DataToolInputStringFilter.model} batter_name
 * @property {DataToolInputStringFilter.model} pitcher_handedness
 * @property {DataToolInputStringFilter.model} batter_handedness
 * @property {DataToolInputStringFilter.model} level
 * @property {DataToolInputStringFilter.model} league
 * @property {DataToolInputNumberFilter.model} velocity
 * @property {DataToolInputNumberFilter.model} spin_rate
 * @property {DataToolInputNumberFilter.model} vertical_break
 * @property {DataToolInputNumberFilter.model} induced_vertical_break
 * @property {DataToolInputNumberFilter.model} horizontal_break
 * @property {DataToolInputNumberFilter.model} efficiency
 * @property {DataToolInputNumberFilter.model} release_height
 * @property {DataToolInputNumberFilter.model} release_side
 * @property {DataToolInputNumberFilter.model} extension
 * @property {DataToolInputNumberFilter.model} exit_velocity
 * @property {DataToolInputNumberFilter.model} launch_angle
 * @property {DataToolInputNumberFilter.model} direction
 * @property {DataToolInputNumberFilter.model} distance
 */
/**
 * @typedef GetDataManagementTool
 * @property {string} page.required
 * @property {DataToolInputData.model} input.required
 */
/**
 * Admin Data management Tool
 * @route POST /admin/datatool/get
 * @param {GetDataManagementTool.model} GetDataManagementTool.body.required - admin login object
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Object
 *      
 * @returns {Error}  Error - Unexpected error
 */
router.post("/datatool/get", [auth, adminAuth], async (req, res) => {
    try {
        let { page, input, sort } = req.body
        let query = {}
        if (!page) page = 1
        if (input && Object.keys(input).length !== 0) {
            query = await AdminController.AdminDataToolFilter(input)
        }

        let options = {
            populate: [{
                path: "bcevent_id",
                select: 'user event_name event_type -_id',
                populate: [
                    { path: "user", select: "fname lname profile -_id", populate: [{ path: 'profile', select: "parentTeam game-type -_id", populate: [{ path: "parentTeam", select: "name type -_id" }] }] }
                ]
            }
            ],
            page: page,
            limit: 100
        };


        if (config.get('ENVIRONMENT') !== "DEV") {
            options['allowDiskUse'] = true
        }
        if (sort && Object.keys(sort).length !== 0) {
            options['sort'] = sort
        }

        let data = await BCDeviceData.paginate(query, options)
        res.send(HelperUtils.successObj("Data Fetched successfully", data))

    } catch (error) {
        console.log(error)
        res.send(HelperUtils.errorObj("something went wrong"));
        return
    }
});


/**
 * @typedef DataToolUpdateData
 * @property {string} pitch_type
 * @property {string} pitcher_team
 * @property {string} batter_team
 * @property {string} pitcher_name
 * @property {string} batter_name
 * @property {string} pitcher_handedness
 * @property {string} batter_handedness
 * @property {string} level
 * @property {string} league
 * @property {number} velocity
 * @property {number} spin_rate
 * @property {number} vertical_break
 * @property {number} induced_vertical_break
 * @property {number} horizontal_break
 * @property {number} efficiency
 * @property {number} release_height
 * @property {number} release_side
 * @property {number} extension
 * @property {number} exit_velocity
 * @property {number} launch_angle
 * @property {number} direction
 * @property {number} distance
 */
/**
 * @typedef updateDataManagementTool
 * @property {Array.<string>} idArr.required
 * @property {DataToolUpdateData.model} update.required
 */
/**
 * Admin Data management Tool
 * @route POST /admin/datatool/update
 * @param {updateDataManagementTool.model} updateDataManagementTool.body.required - admin update object
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Object
 *      
 * @returns {Error}  Error - Unexpected error
 */
router.post("/datatool/update", [auth, adminAuth], async (req, res) => {
    try {
        let { idArr, update } = req.body
        if (!idArr || !idArr.length) return res.send(HelperUtils.errorObj("Ids required!"));
        if (!update || Object.keys(update).length == 0) return res.send(HelperUtils.errorObj("Update Object Required!"));
        let query = {
            _id: { $in: idArr }
        }

        if (update && Object.keys(update).length !== 0) {
            await BCDeviceData.updateMany(query, { $set: update })
        }

        let data = await BCDeviceData.find({ _id: { $in: idArr } })
        res.send(HelperUtils.successObj("Data Updated successfully", data))

    } catch (error) {
        console.log(error)
        res.send(HelperUtils.errorObj("something went wrong"));
        return
    }
});

/**
 * @typedef deleteDataManagementTool
 * @property {Array.<string>} idArr.required
 */
/**
 * Admin Data management Tool
 * @route DELETE /admin/datatool/delete
 * @param {deleteDataManagementTool.model} deleteDataManagementTool.body.required - admin update object
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Object
 *      
 * @returns {Error}  Error - Unexpected error
 */
router.delete("/datatool/delete", [auth, adminAuth], async (req, res) => {
    try {
        let { idArr } = req.body
        if (!idArr || !idArr.length) return res.send(HelperUtils.errorObj("Ids required!"));
        let query = {
            _id: { $in: idArr }
        }

        await BCDeviceData.deleteMany(query)
        res.send(HelperUtils.successObj("Data Deleted successfully"))

    } catch (error) {
        console.log(error)
        res.send(HelperUtils.errorObj("something went wrong"));
        return
    }
});

/**
 * Admin ParentTeam List
 * @route GET /admin/datatool/parentteam/list
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Object
 *      
 * @returns {Error}  Error - Unexpected error
 */
router.get("/datatool/parentteam/list", [auth, adminAuth], async (req, res) => {
    try {
        let data = await ParentTeam.find({}).select('name')
        res.send(HelperUtils.successObj("Data Fetched successfully", data))

    } catch (error) {
        console.log(error)
        res.send(HelperUtils.errorObj("something went wrong"));
        return
    }
});

/**
 * Get Distincted Values
 * @route GET /admin/datatool/distict/list
 * @param {string} key.query.required - search query value here
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Object
 *      
 * @returns {Error}  Error - Unexpected error
 */
router.get("/datatool/distict/list", [auth, adminAuth], async (req, res) => {
    try {
        if (!req.query.key) return res.send(HelperUtils.errorObj("Key value required!"));
        let data = await BCDeviceData.distinct(req.query.key)
        res.send(HelperUtils.successObj("Data Fetched successfully", data))

    } catch (error) {
        console.log(error)
        res.send(HelperUtils.errorObj("something went wrong"));
        return
    }
});

/**
 * Get Data by Id
 * @route GET /admin/datatool/databyId
 * @param {string} id.query.required - search query value here
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Object
 *      
 * @returns {Error}  Error - Unexpected error
 */
router.get("/datatool/databyId", [auth, adminAuth], async (req, res) => {
    try {
        if (!req.query.id) return res.send(HelperUtils.errorObj("id value required!"));
        let data = await BCDeviceData.findById(req.query.id)
        res.send(HelperUtils.successObj("Data Fetched successfully", data))

    } catch (error) {
        console.log(error)
        res.send(HelperUtils.errorObj("something went wrong"));
        return
    }
});

/**
 * Get CSV file
 * @route POST /admin/datatool/csv/generate
 * @group Admin - Admin operation
 * @returns {object} 200 - 
 *      Return Object
 *      
 * @returns {Error}  Error - Unexpected error
 */
router.post("/datatool/csv/generate", [auth, adminAuth], async (req, res) => {
    try {
        let { input, sort } = req.body
        let query = {}
        if (input && Object.keys(input).length !== 0) {
            query = await AdminController.AdminDataToolFilter(input)
        }
        let count = await BCDeviceData.find(query).count()
        let uuid = Date.now()
        if (count > 5000) {
            let path = __dirname + '/./../uploads/stat/export_' + uuid + '.csv'
            let limit = 25000

            await AddTaskToExportProcessingQueue({ query, count, sort, limit, path, uuid, fromEmail: req.user.email })
            return res.send(HelperUtils.successObj("Data Exported", { message: 'You will receive the file on this email' }));
        } else {
            let data = await BCDeviceData.find(query).lean()
            let allColumns = await BCDeviceColumnMap.find({}, { column_name: 1, _id: 0 }).sort({ _id: 1 }).lean()
            allColumns = allColumns.map(x => x.column_name)
            let uuid = Date.now()
            let path = __dirname + '/./../uploads/stat/export_' + uuid + '.csv'
            // let csv = new ObjectsToCsv(data)
            // await csv.toDisk(path, { append: true , allColumns: true })

            const csv = parse(data, { fields: allColumns });
            fs.writeFileSync(path, csv)
            console.log(path);
            res.send(HelperUtils.successObj("Data Exported", { message: 'file exported successfully ', path: config.get('host') + '/stat/export_' + uuid + '.csv' }));
            return
        }

    } catch (error) {
        console.log(error)
        res.send(HelperUtils.errorObj("something went wrong"));
        return
    }
});

module.exports = router;

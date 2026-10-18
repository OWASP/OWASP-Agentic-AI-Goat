import { hasPlatformAdminLevel, projectPlatformUser } from './platformAdmin';
const matrix=[['student',0,false],['student',1,false],['student',2,false],['admin',0,false],['admin',1,true],['admin',2,true],['super_admin',0,false],['super_admin',1,true],['super_admin',2,true]];
test.each(matrix)('presentation policy %s/%s => %s',(role,adminLevel,allowed)=>{
 const input={id:7,role,adminLevel,isAdmin:!allowed,workshop_admin:1,isWorkshopAdmin:!allowed};
 expect(hasPlatformAdminLevel(input)).toBe(allowed);expect(projectPlatformUser(input)).toEqual({...input,isAdmin:allowed,isWorkshopAdmin:allowed});expect(input.isAdmin).toBe(!allowed);
 expect(hasPlatformAdminLevel({role,admin_level:adminLevel})).toBe(allowed);
});
test('missing identity or role cannot become administrator from flags alone',()=>{for(const user of [null,undefined,{}, {isAdmin:true,adminLevel:2},{role:'admin',isAdmin:true}])expect(hasPlatformAdminLevel(user)).toBe(false);});
